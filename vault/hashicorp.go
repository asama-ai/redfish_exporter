package vault

import (
	"context"
	"fmt"

	alog "github.com/apex/log"
	"github.com/hashicorp/vault/api"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

// hashiCorpVaultClient implements the VaultClient interface for HashiCorp Vault
type hashiCorpVaultClient struct {
	client    *api.Client
	kvMount   string
	kvVersion *string // Cached KV version ("v1" or "v2"), nil if not detected yet
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

	logger.Info("HashiCorp Vault client initialized successfully")
	return &hashiCorpVaultClient{
		client:    client,
		kvMount:   config.kvMount,
		kvVersion: nil, // Will be detected on first use
		logger:    logger,
	}, nil
}

// GetCredentials retrieves credentials from HashiCorp Vault.
// It uses the cached KV version, or detects it on first use.
func (h *hashiCorpVaultClient) GetCredentials(ctx context.Context, target string) (*RedfishCreds, error) {
	var cachedVersion string
	if h.kvVersion != nil {
		cachedVersion = *h.kvVersion
	}
	h.logger.Debugf("Retrieving credentials for target: %s (mount: %s, cached version: %s)", target, h.kvMount, cachedVersion)

	// If we haven't detected the KV version yet, try to detect it
	if h.kvVersion == nil {
		return h.detectAndGetCredentials(ctx, target)
	}

	// Use the cached version
	return h.getCredentialsWithVersion(ctx, target, *h.kvVersion)
}

// detectAndGetCredentials detects the KV version and retrieves credentials
func (h *hashiCorpVaultClient) detectAndGetCredentials(ctx context.Context, target string) (*RedfishCreds, error) {
	h.logger.Debugf("KV version not cached, detecting version for target: %s", target)

	// Try KV v2 first
	h.logger.Debugf("Trying KV v2 to read secret from mount: %s, target: %s", h.kvMount, target)
	secret, err := h.client.KVv2(h.kvMount).Get(ctx, target)
	if err == nil && secret != nil && secret.Data != nil {
		version := "v2"
		h.kvVersion = &version // Cache the version
		h.logger.Infof("Detected and cached KV v2 for mount: %s", h.kvMount)
		h.logger.Debugf("Successfully retrieved credentials using KV v2 for target %s", target)
		return h.extractCredentials(secret.Data, target)
	} else {
		h.logger.Debugf("KV v2 failed for target %s: %v, falling back to KV v1", target, err)
	}

	// Fall back to KV v1
	h.logger.Debugf("Trying KV v1 to read secret from mount: %s, target: %s", h.kvMount, target)
	secret, err = h.client.KVv1(h.kvMount).Get(ctx, target)
	if err != nil {
		h.logger.Errorf("Both KV v2 and v1 failed to retrieve secret for target %s. Last error: %v", target, err)
		return nil, fmt.Errorf("failed to retrieve secret for target %s: %w", target, err)
	}
	if secret == nil || secret.Data == nil {
		h.logger.Errorf("No data found for target %s with either KV version", target)
		return nil, fmt.Errorf("no data found for target %s", target)
	}

	version := "v1"
	h.kvVersion = &version // Cache the version
	h.logger.Infof("Detected and cached KV v1 for mount: %s", h.kvMount)
	h.logger.Debugf("Successfully retrieved credentials using KV v1 for target %s", target)
	return h.extractCredentials(secret.Data, target)
}

// getCredentialsWithVersion retrieves credentials using the specified KV version
func (h *hashiCorpVaultClient) getCredentialsWithVersion(ctx context.Context, target string, version string) (*RedfishCreds, error) {
	h.logger.Debugf("Using cached KV %s to read secret from path: %s/%s", version, h.kvMount, target)

	var secret *api.KVSecret
	var err error

	if version == "v2" {
		secret, err = h.client.KVv2(h.kvMount).Get(ctx, target)
		if err == nil && secret != nil && secret.Data != nil {
			return h.extractCredentials(secret.Data, target)
		}
	} else {
		secret, err = h.client.KVv1(h.kvMount).Get(ctx, target)
		if err == nil && secret != nil && secret.Data != nil {
			return h.extractCredentials(secret.Data, target)
		}
	}

	if err != nil {
		h.logger.Errorf("Failed to retrieve secret for target %s using cached KV %s: %v", target, version, err)
		return nil, fmt.Errorf("failed to retrieve secret for target %s: %w", target, err)
	}
	if secret == nil || secret.Data == nil {
		h.logger.Errorf("No data found for target %s using cached KV %s", target, version)
		return nil, fmt.Errorf("no data found for target %s", target)
	}

	return nil, fmt.Errorf("unexpected error retrieving credentials for target %s", target)
}

// extractCredentials extracts username and password from the data map
func (h *hashiCorpVaultClient) extractCredentials(dataMap map[string]any, target string) (*RedfishCreds, error) {
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

	h.logger.Debugf("Successfully extracted credentials for target %s", target)
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
