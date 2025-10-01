package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

// KVVersion represents the KV secret engine version
type KVVersion string

const (
	KVVersionV1 KVVersion = "v1"
	KVVersionV2 KVVersion = "v2"
)

// String returns the string representation of KVVersion
func (k KVVersion) String() string {
	return string(k)
}

// Set implements the kingpin.Value interface
func (k *KVVersion) Set(value string) error {
	switch strings.ToLower(value) {
	case "1", "v1":
		*k = KVVersionV1
	case "2", "v2":
		*k = KVVersionV2
	default:
		return fmt.Errorf("invalid KV version: %s (must be 1/v1 or 2/v2)", value)
	}
	return nil
}

type HashiCorpVaultClient struct {
	client    *api.Client
	kvVersion KVVersion
	kvMount   string
}

var (
	address   *string
	token     *string
	kvVersion *KVVersion
	kvMount   *string
	insecure  *bool
)

func addHashiCorpFlags(a *kingpin.Application) {
	address = a.Flag("hashicorp.address", "Vault address").OverrideDefaultFromEnvar("VAULT_ADDR").String()
	token = a.Flag("hashicorp.token", "Vault token").OverrideDefaultFromEnvar("VAULT_TOKEN").String()
	kvVersion = new(KVVersion)
	a.Flag("hashicorp.kv.version", "KV secret engine version (1/v1 or 2/v2)").Default("v1").OverrideDefaultFromEnvar("VAULT_KV_VERSION").SetValue(kvVersion)
	kvMount = a.Flag("hashicorp.kv.mount", "KV mount path in the Vault").Default("redfish").OverrideDefaultFromEnvar("VAULT_MOUNT_PATH").String()
	insecure = a.Flag("hashicorp.insecure-skip-tls-verify", "Disable TLS verification (insecure, use for testing only)").OverrideDefaultFromEnvar("VAULT_SKIP_VERIFY").Bool()
}

func NewHashiCorpVaultClient() (*HashiCorpVaultClient, error) {
	logger.Debug("Initializing HashiCorp Vault client")

	if token == nil || *token == "" {
		logger.Error("Vault token is required")
		return nil, fmt.Errorf("vault token is required: provide via --hashicorp.token flag or VAULT_TOKEN environment variable")
	}

	config := api.DefaultConfig()

	if address != nil && *address != "" {
		logger.Debugf("Setting Vault address: %s", *address)
		config.Address = *address
	} else {
		logger.Debug("Using default Vault address")
	}

	if insecure != nil && *insecure {
		logger.Warn("TLS verification is disabled - this is insecure and should only be used for testing")
		config.ConfigureTLS(&api.TLSConfig{Insecure: true})
	}

	logger.Debugf("Creating Vault client with KV version: %s, mount: %s", *kvVersion, *kvMount)
	client, err := api.NewClient(config)
	if err != nil {
		logger.Errorf("Failed to create Vault client: %v", err)
		return nil, err
	}

	logger.Debug("Setting Vault token and validating authentication")
	client.SetToken(*token)
	if _, err = client.Auth().Token().LookupSelf(); err != nil {
		logger.Errorf("Vault token validation failed: %v", err)
		return nil, fmt.Errorf("invalid vault token: %v", err)
	}

	logger.Info("HashiCorp Vault client initialized successfully")
	return &HashiCorpVaultClient{
		client:    client,
		kvVersion: *kvVersion,
		kvMount:   *kvMount,
	}, nil
}

// GetCredentials retrieves credentials from HashiCorp Vault.
func (h *HashiCorpVaultClient) GetCredentials(target string) (*RedfishCreds, error) {
	logger.Debugf("Retrieving credentials for target: %s (KV version: %s, mount: %s)", target, h.kvVersion, h.kvMount)

	var secret *api.KVSecret
	var err error
	if h.kvVersion == KVVersionV2 {
		logger.Debugf("Using KV v2 to read secret from path: %s/%s", h.kvMount, target)
		secret, err = h.client.KVv2(h.kvMount).Get(context.Background(), target)
	} else {
		logger.Debugf("Using KV v1 to read secret from path: %s/%s", h.kvMount, target)
		secret, err = h.client.KVv1(h.kvMount).Get(context.Background(), target)
	}
	if err != nil {
		logger.Errorf("Failed to retrieve secret for target %s: %v", target, err)
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		logger.Errorf("No data found for target %s", target)
		return nil, fmt.Errorf("no data found for target %s", target)
	}

	// Handle both KV v1 and v2 data structures
	var dataMap map[string]any
	var ok bool

	if h.kvVersion == KVVersionV2 {
		// KV v2 stores data under "data" key
		logger.Debug("Processing KV v2 data structure")
		dataInterface, exists := secret.Data["data"]
		if !exists {
			logger.Errorf("Data key not found in KV v2 response for target %s", target)
			return nil, fmt.Errorf("data not found for target %s", target)
		}
		dataMap, ok = dataInterface.(map[string]any)
	} else {
		// KV v1 stores data directly in secret.Data
		logger.Debug("Processing KV v1 data structure")
		dataMap = secret.Data
		ok = true
	}

	if !ok {
		logger.Errorf("Unexpected data format for target %s", target)
		return nil, fmt.Errorf("unexpected data format for target %s", target)
	}

	logger.Debugf("Extracting username and password from secret data for target %s", target)
	username, ok := dataMap["username"].(string)
	if !ok {
		logger.Errorf("Username field not found or not a string for target %s", target)
		return nil, fmt.Errorf("username not found for target %s", target)
	}

	password, ok := dataMap["password"].(string)
	if !ok {
		logger.Errorf("Password field not found or not a string for target %s", target)
		return nil, fmt.Errorf("password not found for target %s", target)
	}

	logger.Debugf("Successfully retrieved credentials for target %s", target)
	return &RedfishCreds{
		Username: username,
		Password: password,
	}, nil
}
