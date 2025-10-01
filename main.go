package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	alog "github.com/apex/log"
	"github.com/asama-ai/redfish_exporter/collector"
	"github.com/asama-ai/redfish_exporter/vault"
	kitlog "github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	Version       string
	BuildRevision string
	BuildBranch   string
	BuildTime     string
	BuildHost     string
	rootLoggerCtx *alog.Entry

	configFile = kingpin.Flag(
		"config.file",
		"Path to configuration file.",
	).String()
	webConfig     = webflag.AddFlags(kingpin.CommandLine)
	listenAddress = kingpin.Flag(
		"web.listen-address",
		"Address to listen on for web interface and telemetry.",
	).Default(":9610").String()
	sc = &SafeConfig{
		C: &Config{},
	}
	reloadCh     chan chan error
	vaultManager *vault.VaultManager
)

func init() {
	rootLoggerCtx = alog.WithFields(alog.Fields{
		"app": "redfish_exporter",
	})

	hostname, _ := os.Hostname()
	rootLoggerCtx.Infof("version %s, build reversion %s, build branch %s, build at %s on host %s", Version, BuildRevision, BuildBranch, BuildTime, hostname)
}

func reloadHandler(configLoggerCtx *alog.Entry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" || r.Method == "PUT" {
			configLoggerCtx.Info("Triggered configuration reload from /-/reload HTTP endpoint")
			err := sc.ReloadConfig(*configFile)
			if err != nil {
				configLoggerCtx.WithError(err).Error("failed to reload config file")
				http.Error(w, "failed to reload config file", http.StatusInternalServerError)
			}
			configLoggerCtx.WithField("operation", "sc.ReloadConfig").Info("config file reloaded")

			w.WriteHeader(http.StatusOK)
			_, err = io.WriteString(w, "Configuration reloaded successfully!")
			if err != nil {
				configLoggerCtx.Warn("failed to send configuration reload status message")
			}
		} else {
			http.Error(w, "Only PUT and POST methods are allowed", http.StatusBadRequest)
		}
	}
}

func SetLogLevel() {
	logLevel, err := alog.ParseLevel(sc.AppLogLevel())
	if err != nil {
		logLevel = alog.InfoLevel
	}

	alog.SetLevel(logLevel)
}

// define new http handleer
func metricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		registry := prometheus.NewRegistry()
		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, "'target' parameter must be specified", 400)
			return
		}
		targetLoggerCtx := rootLoggerCtx.WithField("target", target)
		targetLoggerCtx.Info("scraping target host")

		var (
			hostConfig *HostConfig
			err        error
			ok         bool
			group      []string
		)

		group, ok = r.URL.Query()["group"]

		if ok && len(group[0]) >= 1 {
			// Trying to get hostConfig from group.
			if hostConfig, err = sc.HostConfigForGroup(group[0]); err != nil {
				targetLoggerCtx.WithError(err).Error("error getting credentials")
				return
			}
		}
		if hostConfig == nil && vaultManager != nil {
			creds, err := vaultManager.GetCredentials(context.Background(), target)
			if err != nil {
				targetLoggerCtx.WithError(err).Error("error getting credentials from vault")
			} else {
				hostConfig = &HostConfig{
					Username: creds.Username,
					Password: creds.Password,
				}
			}
		}
		// Always falling back to single host config when group config failed.
		if hostConfig == nil {
			if hostConfig, err = sc.HostConfigForTarget(target); err != nil {
				targetLoggerCtx.WithError(err).Error("error getting credentials")
				return
			}
		}

		collector := collector.NewRedfishCollector(target, hostConfig.Username, hostConfig.Password, targetLoggerCtx)
		registry.MustRegister(collector)
		gatherers := prometheus.Gatherers{
			prometheus.DefaultGatherer,
			registry,
		}
		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)

	}
}

func main() {

	log.AddFlags(kingpin.CommandLine)
	kingpin.HelpFlag.Short('h')

	vault.AddVaultFlags(kingpin.CommandLine)
	kingpin.Parse()

	kitlogger := kitlog.NewLogfmtLogger(os.Stderr)
	configLoggerCtx := rootLoggerCtx.WithField("config", *configFile)
	configLoggerCtx.Info("starting app")
	// load config  first time

	if err := sc.ReloadConfig(*configFile); err != nil {
		configLoggerCtx.WithError(err).Error("error parsing config file")
		panic(err)
	}

	configLoggerCtx.WithField("operation", "sc.ReloadConfig").Info("config file loaded")

	SetLogLevel()

	if vault.IsVaultEnabled() {
		// Create vault logger context
		vaultLoggerCtx := rootLoggerCtx.WithField("component", "vault")

		// Create vault configuration (only type, HashiCorp-specific config is handled internally)
		vaultConfig := &vault.VaultConfig{
			Type: vault.GetVaultType(),
		}

		// Initialize vault manager
		var err error
		vaultManager, err = vault.NewVaultManager(vaultConfig, vaultLoggerCtx)
		if err != nil {
			rootLoggerCtx.WithError(err).Fatal("Failed to initialize vault manager")
		}

		// Perform health check to confirm Vault connection is successful
		vaultLoggerCtx.Info("Performing Vault health check...")
		if err := vaultManager.HealthCheck(context.Background()); err != nil {
			rootLoggerCtx.WithError(err).Fatal("Vault health check failed - connection is not working")
		}
		vaultLoggerCtx.Info("Vault health check passed - connection is working")

		// Ensure vault manager is closed on exit
		defer func() {
			if err := vaultManager.Close(); err != nil {
				rootLoggerCtx.WithError(err).Error("Failed to close vault manager")
			}
		}()
	}

	// load config in background to watch for config changes
	hup := make(chan os.Signal, 1)
	reloadCh = make(chan chan error)
	signal.Notify(hup, syscall.SIGHUP)

	go func() {
		for {
			select {
			case <-hup:
				if err := sc.ReloadConfig(*configFile); err != nil {
					configLoggerCtx.WithError(err).Error("failed to reload config file")
					break
				}
				configLoggerCtx.WithField("operation", "sc.ReloadConfig").Info("config file reload")
			case rc := <-reloadCh:
				if err := sc.ReloadConfig(*configFile); err != nil {
					configLoggerCtx.WithError(err).Error("failed to reload config file")
					rc <- err
					break
				}
				configLoggerCtx.WithField("operation", "sc.ReloadConfig").Info("config file reloaded")
				rc <- nil
			}
		}
	}()

	http.Handle("/redfish", metricsHandler())                // Regular metrics endpoint for local Redfish metrics.
	http.Handle("/-/reload", reloadHandler(configLoggerCtx)) // HTTP endpoint for triggering configuration reload
	http.Handle("/metrics", promhttp.Handler())

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// nolint
		w.Write([]byte(`<html>
            <head>
            <title>Redfish Exporter</title>
            </head>
						<body>
            <h1>redfish Exporter</h1>
            <form action="/redfish">
            <label>Target:</label> <input type="text" name="target" placeholder="X.X.X.X" value="1.2.3.4"><br>
            <label>Group:</label> <input type="text" name="group" placeholder="group (optional)" value=""><br>
            <input type="submit" value="Submit">
						</form>
						<p><a href="/metrics">Local metrics</a></p>
            </body>
            </html>`))
	})

	rootLoggerCtx.Infof("app started. listening on %s", *listenAddress)
	srv := &http.Server{Addr: *listenAddress}
	err := web.ListenAndServe(srv, *webConfig, kitlogger)
	if err != nil {
		log.Fatal(err)
	}
}
