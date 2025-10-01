package vault

import (
	"context"
	"fmt"
	"strings"

	alog "github.com/apex/log"
	"github.com/hashicorp/vault/api"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

// getMapKeys returns the keys of a map as a slice of strings
func getMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

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

// hashiCorpVaultClient implements the VaultClient interface for HashiCorp Vault
type hashiCorpVaultClient struct {
	client    *api.Client
	kvVersion KVVersion
	kvMount   string
	logger    *alog.Entry
}

// Legacy global variables for backward compatibility
var (
	address  *string
	token    *string
	kvMount  *string
	insecure *bool
)

func addHashiCorpFlags(a *kingpin.Application) {
	address = a.Flag("hashicorp.address", "Vault address").OverrideDefaultFromEnvar("VAULT_ADDR").String()
	token = a.Flag("hashicorp.token", "Vault token").OverrideDefaultFromEnvar("VAULT_TOKEN").String()
	kvMount = a.Flag("hashicorp.kv.mount", "KV mount path in the Vault").Default("redfish").OverrideDefaultFromEnvar("VAULT_MOUNT_PATH").String()
	insecure = a.Flag("hashicorp.insecure-skip-tls-verify", "Disable TLS verification (insecure, use for testing only)").OverrideDefaultFromEnvar("VAULT_SKIP_VERIFY").Bool()
}

// hashiCorpConfig holds HashiCorp-specific configuration
type hashiCorpConfig struct {
	address  string
	token    string
	kvMount  string
	insecure bool
}

// NewHashiCorpVaultManager creates a VaultManager for HashiCorp Vault using the internal configuration
func NewHashiCorpVaultManager(logger *alog.Entry) (*VaultManager, error) {
	// Create internal HashiCorp configuration from flags
	config := &VaultConfig{
		Type: VaultTypeHashiCorp,
	}

	// Create HashiCorp-specific config for the client
	hashicorpConfig := &hashiCorpConfig{
		address:  *address,
		token:    *token,
		kvMount:  *kvMount,
		insecure: *insecure,
	}

	// Create the HashiCorp client
	client, err := newHashiCorpVaultClient(hashicorpConfig, logger)
	if err != nil {
		return nil, err
	}

	return &VaultManager{
		client: client,
		logger: logger,
		config: config,
	}, nil
}

// detectKVVersion auto-detects the KV version for the given mount path
func detectKVVersion(client *api.Client, mountPath string, logger *alog.Entry) (KVVersion, error) {
	// Normalize mount path by trimming trailing slash and adding it back
	normalizedPath := strings.TrimSuffix(mountPath, "/") + "/"
	logger.Debugf("Auto-detecting KV version for mount path: %s (normalized: %s)", mountPath, normalizedPath)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return "", fmt.Errorf("failed to list mounts: %w", err)
	}

	// Use comma-ok style to check if mount exists
	mount, exists := mounts[normalizedPath]
	if !exists {
		return "", fmt.Errorf("mount path %s not found in Vault", mountPath)
	}

	// Check if it's a KV secret engine
	if mount.Type != "kv" {
		return "", fmt.Errorf("mount path %s exists but is not a KV secret engine (type: %s)", mountPath, mount.Type)
	}

	// Check if it's KV v2 by looking for the version field
	if version, exists := mount.Options["version"]; exists && version == "2" {
		logger.Debugf("Detected KV v2 for mount path: %s", mountPath)
		return KVVersionV2, nil
	}

	logger.Debugf("Detected KV v1 for mount path: %s", mountPath)
	return KVVersionV1, nil
}

// newHashiCorpVaultClient creates a new HashiCorp Vault client
func newHashiCorpVaultClient(config *hashiCorpConfig, logger *alog.Entry) (*hashiCorpVaultClient, error) {
	if config == nil {
		return nil, fmt.Errorf("vault config cannot be nil")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	logger.Debug("Initializing HashiCorp Vault client")

	if config.token == "" {
		logger.Error("Vault token is required")
		return nil, fmt.Errorf("vault token is required")
	}

	vaultConfig := api.DefaultConfig()

	if config.address != "" {
		logger.Debugf("Setting Vault address: %s", config.address)
		vaultConfig.Address = config.address
	} else {
		logger.Debug("Using default Vault address")
	}

	if config.insecure {
		logger.Warn("TLS verification is disabled - this is insecure and should only be used for testing")
		vaultConfig.ConfigureTLS(&api.TLSConfig{Insecure: true})
	}

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		logger.Errorf("Failed to create Vault client: %v", err)
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	logger.Debug("Setting Vault token and validating authentication")
	client.SetToken(config.token)
	if _, err = client.Auth().Token().LookupSelf(); err != nil {
		logger.Errorf("Vault token validation failed: %v", err)
		return nil, fmt.Errorf("invalid vault token: %w", err)
	}

	// Auto-detect KV version
	detectedVersion, err := detectKVVersion(client, config.kvMount, logger)
	if err != nil {
		logger.Errorf("Failed to auto-detect KV version: %v", err)
		return nil, fmt.Errorf("failed to auto-detect KV version for mount %s: %w", config.kvMount, err)
	}
	logger.Infof("Auto-detected KV version: %s for mount: %s", detectedVersion, config.kvMount)

	logger.Info("HashiCorp Vault client initialized successfully")
	return &hashiCorpVaultClient{
		client:    client,
		kvVersion: detectedVersion,
		kvMount:   config.kvMount,
		logger:    logger,
	}, nil
}

// GetCredentials retrieves credentials from HashiCorp Vault.
func (h *hashiCorpVaultClient) GetCredentials(ctx context.Context, target string) (*RedfishCreds, error) {
	h.logger.Debugf("Retrieving credentials for target: %s (KV version: %s, mount: %s)", target, h.kvVersion, h.kvMount)

	var secret *api.KVSecret
	var err error
	if h.kvVersion == KVVersionV2 {
		h.logger.Debugf("Using KV v2 to read secret from path: %s/%s", h.kvMount, target)
		secret, err = h.client.KVv2(h.kvMount).Get(ctx, target)
	} else {
		h.logger.Debugf("Using KV v1 to read secret from path: %s/%s", h.kvMount, target)
		secret, err = h.client.KVv1(h.kvMount).Get(ctx, target)
	}
	if err != nil {
		h.logger.Errorf("Failed to retrieve secret for target %s: %v", target, err)
		return nil, fmt.Errorf("failed to retrieve secret for target %s: %w", target, err)
	}
	if secret == nil || secret.Data == nil {
		h.logger.Errorf("No data found for target %s", target)
		return nil, fmt.Errorf("no data found for target %s", target)
	}

	h.logger.Debugf("Secret data structure for target %s: %+v", target, secret.Data)

	// Handle both KV v1 and v2 data structures
	var dataMap map[string]any
	var ok bool

	if h.kvVersion == KVVersionV2 {
		// KV v2 stores data under "data" key
		h.logger.Debug("Processing KV v2 data structure")
		h.logger.Debugf("KV v2 secret.Data keys: %v", getMapKeys(secret.Data))

		// Check if the response has the expected KV v2 structure
		if dataInterface, exists := secret.Data["data"]; exists {
			dataMap, ok = dataInterface.(map[string]any)
		} else {
			h.logger.Errorf("Data key not found in KV v2 response for target %s. Available keys: %v", target, getMapKeys(secret.Data))
			return nil, fmt.Errorf("data not found for target %s", target)
		}
	} else {
		// KV v1 stores data directly in secret.Data
		h.logger.Debug("Processing KV v1 data structure")
		dataMap = secret.Data
		ok = true
	}

	if !ok {
		h.logger.Errorf("Unexpected data format for target %s", target)
		return nil, fmt.Errorf("unexpected data format for target %s", target)
	}

	h.logger.Debugf("Extracting username and password from secret data for target %s", target)
	username, ok := dataMap["username"].(string)
	if !ok {
		h.logger.Errorf("Username field not found or not a string for target %s", target)
		return nil, fmt.Errorf("username not found for target %s", target)
	}

	password, ok := dataMap["password"].(string)
	if !ok {
		h.logger.Errorf("Password field not found or not a string for target %s", target)
		return nil, fmt.Errorf("password not found for target %s", target)
	}

	h.logger.Debugf("Successfully retrieved credentials for target %s", target)
	return &RedfishCreds{
		Username: username,
		Password: password,
	}, nil
}

// HealthCheck performs a health check on the HashiCorp Vault client
func (h *hashiCorpVaultClient) HealthCheck(ctx context.Context) error {
	h.logger.Debug("Performing health check on HashiCorp Vault client")

	// Try to lookup the token to verify connectivity and authentication
	_, err := h.client.Auth().Token().LookupSelf()
	if err != nil {
		h.logger.Errorf("Health check failed: %v", err)
		return fmt.Errorf("vault health check failed: %w", err)
	}

	h.logger.Debug("Health check passed")
	return nil
}

// Close closes the HashiCorp Vault client
func (h *hashiCorpVaultClient) Close() error {
	h.logger.Debug("Closing HashiCorp Vault client")
	// The HashiCorp Vault client doesn't have an explicit close method
	// but we can clear the token for security
	if h.client != nil {
		h.client.ClearToken()
	}
	return nil
}
