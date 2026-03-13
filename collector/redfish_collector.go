package collector

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"crypto/tls"

	"github.com/apex/log"
	"github.com/prometheus/client_golang/prometheus"
	gofish "github.com/stmcginnis/gofish"
	gofishcommon "github.com/stmcginnis/gofish/common"
	redfish "github.com/stmcginnis/gofish/redfish"
)

// Metric name parts.
const (
	// Exporter namespace.
	namespace = "redfish"
	// Subsystem(s).
	exporter = "exporter"
	// Math constant for picoseconds to seconds.
	picoSeconds = 1e12
)

// Metric descriptors.
var (
	totalScrapeDurationDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, exporter, "collector_duration_seconds"),
		"Collector time duration.",
		nil, nil,
	)
)

// RedfishCollector collects redfish metrics. It implements prometheus.Collector.
type RedfishCollector struct {
	redfishClient *gofish.APIClient
	collectors    map[string]prometheus.Collector
	redfishUp     prometheus.Gauge
}

// NewRedfishCollector return RedfishCollector
func NewRedfishCollector(host string, username string, password string, logger *log.Entry) *RedfishCollector {
	var collectors map[string]prometheus.Collector
	collectorLogCtx := logger
	redfishClient, err := newRedfishClient(host, username, password)
	if err != nil {
		collectorLogCtx.WithError(err).Error("error creating redfish client")
	} else {
		chassisCollector := NewChassisCollector(redfishClient, collectorLogCtx)
		systemCollector := NewSystemCollector(redfishClient, collectorLogCtx)
		managerCollector := NewManagerCollector(redfishClient, collectorLogCtx)

		collectors = map[string]prometheus.Collector{"chassis": chassisCollector, "system": systemCollector, "manager": managerCollector}
	}

	return &RedfishCollector{
		redfishClient: redfishClient,
		collectors:    collectors,
		redfishUp: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: "",
				Name:      "up",
				Help:      "redfish up",
			},
		),
	}
}

// Describe implements prometheus.Collector.
func (r *RedfishCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, collector := range r.collectors {
		collector.Describe(ch)
	}

}

// Collect implements prometheus.Collector.
func (r *RedfishCollector) Collect(ch chan<- prometheus.Metric) {

	scrapeTime := time.Now()
	if r.redfishClient != nil {
		defer r.redfishClient.Logout()
		r.redfishUp.Set(1)
		wg := &sync.WaitGroup{}
		wg.Add(len(r.collectors))

		for _, collector := range r.collectors {
			go func(collector prometheus.Collector) {
				defer wg.Done()
				collector.Collect(ch)
			}(collector)
		}
		wg.Wait()
	} else {
		r.redfishUp.Set(0)
	}

	ch <- r.redfishUp
	ch <- prometheus.MustNewConstMetric(totalScrapeDurationDesc, prometheus.GaugeValue, time.Since(scrapeTime).Seconds())
}

// proxyForRequest returns a Proxy function that uses HTTP_PROXY/HTTPS_PROXY for all
// requests when set, including localhost/loopback. Go's ProxyFromEnvironment skips
// the proxy for loopback, so with target 127.0.0.1 no exporter traffic would go
// through redpool; this allows the golden script (and any proxy-in-the-middle case)
// to send all traffic through the proxy.
func proxyForRequest() func(*http.Request) (*url.URL, error) {
	httpProxy := strings.TrimSpace(os.Getenv("HTTP_PROXY"))
	if httpProxy == "" {
		httpProxy = strings.TrimSpace(os.Getenv("http_proxy"))
	}
	httpsProxy := strings.TrimSpace(os.Getenv("HTTPS_PROXY"))
	if httpsProxy == "" {
		httpsProxy = strings.TrimSpace(os.Getenv("https_proxy"))
	}
	if httpProxy == "" && httpsProxy == "" {
		return http.ProxyFromEnvironment
	}
	var httpURL, httpsURL *url.URL
	if httpProxy != "" {
		httpURL, _ = url.Parse(httpProxy)
	}
	if httpsProxy != "" {
		httpsURL, _ = url.Parse(httpsProxy)
	}
	if httpsURL == nil {
		httpsURL = httpURL
	}
	if httpURL == nil {
		httpURL = httpsURL
	}
	return func(req *http.Request) (*url.URL, error) {
		if req == nil || req.URL == nil {
			return nil, nil
		}
		if req.URL.Scheme == "https" && httpsURL != nil {
			return httpsURL, nil
		}
		if req.URL.Scheme == "http" && httpURL != nil {
			return httpURL, nil
		}
		return nil, nil
	}
}

func newRedfishClient(host string, username string, password string) (*gofish.APIClient, error) {
	scheme := "https"
	if s := os.Getenv("REDFISH_SCHEME"); s == "http" {
		scheme = "http"
	}
	url := fmt.Sprintf("%s://%s", scheme, host)

	// Use proxy for all requests when HTTP_PROXY/HTTPS_PROXY is set, including localhost.
	// Go's ProxyFromEnvironment skips the proxy for loopback, so target 127.0.0.1 would
	// bypass redpool; this allows the golden script (and proxy-in-the-middle) to work.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Proxy: proxyForRequest(),
	}

	config := gofish.ClientConfig{
		Endpoint: url,
		Username: username,
		Password: password,
		Insecure: true,
		HTTPClient: &http.Client{
			Transport: transport,
		},
	}

	redfishClient, err := gofish.Connect(config)
	if err != nil {
		return nil, err
	}
	return redfishClient, nil
}

func parseCommonStatusHealth(status gofishcommon.Health) (float64, bool) {
	if bytes.Equal([]byte(status), []byte("OK")) {
		return float64(1), true
	} else if bytes.Equal([]byte(status), []byte("Warning")) {
		return float64(2), true
	} else if bytes.Equal([]byte(status), []byte("Critical")) {
		return float64(3), true
	}
	return float64(0), false
}

func parseCommonStatusState(status gofishcommon.State) (float64, bool) {

	if bytes.Equal([]byte(status), []byte("")) {
		return float64(0), false
	} else if bytes.Equal([]byte(status), []byte("Enabled")) {
		return float64(1), true
	} else if bytes.Equal([]byte(status), []byte("Disabled")) {
		return float64(2), true
	} else if bytes.Equal([]byte(status), []byte("StandbyOffinline")) {
		return float64(3), true
	} else if bytes.Equal([]byte(status), []byte("StandbySpare")) {
		return float64(4), true
	} else if bytes.Equal([]byte(status), []byte("InTest")) {
		return float64(5), true
	} else if bytes.Equal([]byte(status), []byte("Starting")) {
		return float64(6), true
	} else if bytes.Equal([]byte(status), []byte("Absent")) {
		return float64(7), true
	} else if bytes.Equal([]byte(status), []byte("UnavailableOffline")) {
		return float64(8), true
	} else if bytes.Equal([]byte(status), []byte("Deferring")) {
		return float64(9), true
	} else if bytes.Equal([]byte(status), []byte("Quiesced")) {
		return float64(10), true
	} else if bytes.Equal([]byte(status), []byte("Updating")) {
		return float64(11), true
	}
	return float64(0), false
}

func parseCommonSeverityState(severity redfish.EventSeverity) (float64, bool) {
	if bytes.Equal([]byte(severity), []byte("OK")) {
		return float64(1), true
	} else if bytes.Equal([]byte(severity), []byte("Warning")) {
		return float64(2), true
	} else if bytes.Equal([]byte(severity), []byte("Critical")) {
		return float64(3), true
	}
	return float64(0), false
}

func parseCommonPowerState(status redfish.PowerState) (float64, bool) {
	if bytes.Equal([]byte(status), []byte("On")) {
		return float64(1), true
	} else if bytes.Equal([]byte(status), []byte("Off")) {
		return float64(2), true
	} else if bytes.Equal([]byte(status), []byte("PoweringOn")) {
		return float64(3), true
	} else if bytes.Equal([]byte(status), []byte("PoweringOff")) {
		return float64(4), true
	}
	return float64(0), false
}

func parseLinkStatus(status redfish.LinkStatus) (float64, bool) {
	if bytes.Equal([]byte(status), []byte("LinkUp")) {
		return float64(1), true
	} else if bytes.Equal([]byte(status), []byte("NoLink")) {
		return float64(2), true
	} else if bytes.Equal([]byte(status), []byte("LinkDown")) {
		return float64(3), true
	}
	return float64(0), false
}

func parsePortLinkStatus(status redfish.PortLinkStatus) (float64, bool) {
	if bytes.Equal([]byte(status), []byte("Up")) {
		return float64(1), true
	}
	return float64(0), false
}
func boolToFloat64(data bool) float64 {

	if data {
		return float64(1)
	}
	return float64(0)

}

func parsePhySecReArmMethod(method redfish.IntrusionSensorReArm) (float64, bool) {
	if bytes.Equal([]byte(method), []byte("Manual")) {
		return float64(1), true
	}
	if bytes.Equal([]byte(method), []byte("Automatic")) {
		return float64(2), true
	}

	return float64(0), false
}

func parsePhySecIntrusionSensor(method redfish.IntrusionSensor) (float64, bool) {
	if bytes.Equal([]byte(method), []byte("Normal")) {
		return float64(1), true
	}
	if bytes.Equal([]byte(method), []byte("TamperingDetected")) {
		return float64(2), true
	}
	if bytes.Equal([]byte(method), []byte("HardwareIntrusion")) {
		return float64(3), true
	}

	return float64(0), false
}
