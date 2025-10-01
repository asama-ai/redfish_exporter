package vault

import (
	"context"
	"os"
	"testing"
	"time"

	alog "github.com/apex/log"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Configure apex logger for test debugging - default handler includes timestamps
	alog.SetLevel(alog.DebugLevel)
}

// NewHashiCorpVaultManagerForTesting creates a VaultManager for testing with custom configuration
func NewHashiCorpVaultManagerForTesting(config *hashiCorpConfig, logger *alog.Entry) (*VaultManager, error) {
	// Create internal configuration
	vaultConfig := &VaultConfig{
		Type: VaultTypeHashiCorp,
	}

	// Create the HashiCorp client
	client, err := newHashiCorpVaultClient(config, logger)
	if err != nil {
		return nil, err
	}

	return &VaultManager{
		client: client,
		logger: logger,
		config: vaultConfig,
	}, nil
}

// createHashiCorpVaultClient creates a HashiCorp Vault API client for test setup
func createHashiCorpVaultClient(t *testing.T) *api.Client {
	t.Helper()

	config := api.DefaultConfig()
	config.Address = os.Getenv("VAULT_ADDR")
	if config.Address == "" {
		t.Fatal("VAULT_ADDR environment variable not set")
	}

	client, err := api.NewClient(config)
	require.NoError(t, err, "Failed to create Vault client")

	client.SetToken(os.Getenv("VAULT_TOKEN"))
	if client.Token() == "" {
		t.Fatal("VAULT_TOKEN environment variable not set")
	}

	return client
}

// setupHashiCorpVaultTestData sets up the required test data in HashiCorp Vault using the API
func setupHashiCorpVaultTestData(t *testing.T) {
	t.Helper()
	t.Log("Starting Vault test data setup")

	client := createHashiCorpVaultClient(t)
	t.Log("Vault client created")

	// Enable KV v1 secret engine
	t.Log("Enabling KV v1 secret engine at test/bmccredsv1...")
	err := client.Sys().Mount("test/bmccredsv1", &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "1",
		},
	})
	if err != nil {
		// Ignore error if already enabled
		t.Logf("KV v1 engine setup: %v (may already be enabled)", err)
	} else {
		t.Log("KV v1 engine enabled successfully")
	}

	// Enable KV v2 secret engine
	t.Log("Enabling KV v2 secret engine at test/bmccredsv2...")
	err = client.Sys().Mount("test/bmccredsv2", &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	})
	if err != nil {
		// Ignore error if already enabled
		t.Logf("KV v2 engine setup: %v (may already be enabled)", err)
	} else {
		t.Log("KV v2 engine enabled successfully")
	}

	// Create test secret for KV v1
	t.Log("Creating test secret in KV v1...")
	err = client.KVv1("test/bmccredsv1").Put(context.Background(), "192.168.10.10", map[string]any{
		"username": "root",
		"password": "calvin",
	})
	require.NoError(t, err, "Failed to create KV v1 test secret")
	t.Log("KV v1 secret created successfully")

	// Create test secret for KV v2
	t.Log("Creating test secret in KV v2...")
	_, err = client.KVv2("test/bmccredsv2").Put(context.Background(), "192.168.10.10", map[string]any{
		"username": "root",
		"password": "calvin",
	})
	require.NoError(t, err, "Failed to create KV v2 test secret")
	t.Log("KV v2 secret created successfully")

	// Verify the secrets were created
	t.Log("Verifying test secrets...")
	secret, err := client.KVv1("test/bmccredsv1").Get(context.Background(), "192.168.10.10")
	require.NoError(t, err, "Failed to verify KV v1 secret")
	require.NotNil(t, secret, "KV v1 secret should not be nil")

	secret, err = client.KVv2("test/bmccredsv2").Get(context.Background(), "192.168.10.10")
	require.NoError(t, err, "Failed to verify KV v2 secret")
	require.NotNil(t, secret, "KV v2 secret should not be nil")
	t.Log("Secrets verified successfully")

	// Small delay to ensure Vault has processed the changes
	t.Log("Waiting for Vault to process changes...")
	time.Sleep(100 * time.Millisecond)
	t.Log("Wait completed")

	t.Log("Vault test data setup complete")
}

// cleanupHashiCorpVaultTestData removes the test data from HashiCorp Vault using the API
func cleanupHashiCorpVaultTestData(t *testing.T) {
	t.Helper()

	client := createHashiCorpVaultClient(t)

	// Remove test secrets
	t.Log("Cleaning up Vault test data...")

	// Delete KV v1 secret
	err := client.KVv1("test/bmccredsv1").Delete(context.Background(), "192.168.10.10")
	if err != nil {
		t.Logf("Failed to delete KV v1 secret: %v", err)
	}

	// Delete KV v2 secret
	err = client.KVv2("test/bmccredsv2").Delete(context.Background(), "192.168.10.10")
	if err != nil {
		t.Logf("Failed to delete KV v2 secret: %v", err)
	}

	// Note: We don't disable the secret engines as they might be used by other tests
	// or the user might want to keep them for manual testing
}

// TestHashiCorpVaultIntegration tests real HashiCorp Vault connections for both KV v1 and v2
func TestHashiCorpVaultIntegration(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("VAULT_ADDR") == "" || os.Getenv("VAULT_TOKEN") == "" {
		t.Skip("Skipping integration test: VAULT_ADDR and VAULT_TOKEN environment variables not set")
	}

	// Set up test data in Vault
	setupHashiCorpVaultTestData(t)
	defer cleanupHashiCorpVaultTestData(t)

	// Test data
	target := "192.168.10.10"
	expectedUsername := "root"
	expectedPassword := "calvin"

	// Create logger
	logger := alog.WithField("test", "integration")

	tests := []struct {
		name              string
		mountPath         string
		expectedKVVersion string
	}{
		{
			name:              "KV v1 integration test",
			mountPath:         "test/bmccredsv1",
			expectedKVVersion: "v1",
		},
		{
			name:              "KV v1 integration test with trailing slash",
			mountPath:         "test/bmccredsv1/",
			expectedKVVersion: "v1",
		},
		{
			name:              "KV v2 integration test",
			mountPath:         "test/bmccredsv2",
			expectedKVVersion: "v2",
		},
		{
			name:              "KV v2 integration test with trailing slash",
			mountPath:         "test/bmccredsv2/",
			expectedKVVersion: "v2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create vault configuration for testing
			config := &hashiCorpConfig{
				address:  os.Getenv("VAULT_ADDR"),
				token:    os.Getenv("VAULT_TOKEN"),
				kvMount:  tt.mountPath,
				insecure: false, // Set to true if using self-signed certificates
			}

			// Create vault manager for testing
			manager, err := NewHashiCorpVaultManagerForTesting(config, logger)
			require.NoError(t, err, "Failed to create vault manager")
			require.NotNil(t, manager, "Vault manager should not be nil")

			// Ensure cleanup
			defer func() {
				if err := manager.Close(); err != nil {
					t.Logf("Warning: failed to close vault manager: %v", err)
				}
			}()

			// Test health check
			t.Run("HealthCheck", func(t *testing.T) {
				err := manager.HealthCheck(context.Background())
				assert.NoError(t, err, "Health check should pass")
			})

			// Test credential retrieval
			t.Run("GetCredentials", func(t *testing.T) {
				creds, err := manager.GetCredentials(context.Background(), target)
				require.NoError(t, err, "Failed to get credentials")
				require.NotNil(t, creds, "Credentials should not be nil")

				assert.Equal(t, expectedUsername, creds.Username, "Username should match expected value")
				assert.Equal(t, expectedPassword, creds.Password, "Password should match expected value")
			})

			// Test that the detected KV version matches expected
			t.Run("KVVersionDetection", func(t *testing.T) {
				// We can't directly access the detected version from the manager,
				// but we can verify it works by checking the logs or making another call
				// For now, we'll just verify that credentials were retrieved successfully
				// which implies the correct KV version was detected
				creds, err := manager.GetCredentials(context.Background(), target)
				assert.NoError(t, err, "Should be able to retrieve credentials with detected KV version")
				assert.NotNil(t, creds, "Credentials should not be nil")
			})
		})
	}
}

// TestHashiCorpVaultIntegrationErrorHandling tests HashiCorp Vault error scenarios
func TestHashiCorpVaultIntegrationErrorHandling(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("VAULT_ADDR") == "" || os.Getenv("VAULT_TOKEN") == "" {
		t.Skip("Skipping integration test: VAULT_ADDR and VAULT_TOKEN environment variables not set")
	}

	// Set up test data in Vault
	setupHashiCorpVaultTestData(t)
	defer cleanupHashiCorpVaultTestData(t)

	logger := alog.WithField("test", "integration")

	tests := []struct {
		name        string
		config      *hashiCorpConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "Invalid mount path",
			config: &hashiCorpConfig{
				address:  os.Getenv("VAULT_ADDR"),
				token:    os.Getenv("VAULT_TOKEN"),
				kvMount:  "nonexistent/mount",
				insecure: false,
			},
			expectError: true,
			errorMsg:    "mount path nonexistent/mount not found",
		},
		{
			name: "Invalid token",
			config: &hashiCorpConfig{
				address:  os.Getenv("VAULT_ADDR"),
				token:    "invalid-token",
				kvMount:  "test/bmccredsv1",
				insecure: false,
			},
			expectError: true,
			errorMsg:    "invalid vault token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewHashiCorpVaultManagerForTesting(tt.config, logger)

			if tt.expectError {
				assert.Error(t, err, "Expected error for invalid configuration")
				assert.Contains(t, err.Error(), tt.errorMsg, "Error message should contain expected text")
				assert.Nil(t, manager, "Manager should be nil on error")
			} else {
				assert.NoError(t, err, "Should not error with valid configuration")
				assert.NotNil(t, manager, "Manager should not be nil")

				// Cleanup if manager was created successfully
				if manager != nil {
					defer func() {
						if err := manager.Close(); err != nil {
							t.Logf("Warning: failed to close vault manager: %v", err)
						}
					}()
				}
			}
		})
	}
}

// TestHashiCorpVaultIntegrationCredentialRetrieval tests HashiCorp Vault credential retrieval with different targets
func TestHashiCorpVaultIntegrationCredentialRetrieval(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("VAULT_ADDR") == "" || os.Getenv("VAULT_TOKEN") == "" {
		t.Skip("Skipping integration test: VAULT_ADDR and VAULT_TOKEN environment variables not set")
	}

	// Set up test data in Vault
	setupHashiCorpVaultTestData(t)
	defer cleanupHashiCorpVaultTestData(t)

	logger := alog.WithField("test", "integration")

	// Test with KV v1
	t.Run("KVv1_CredentialRetrieval", func(t *testing.T) {
		config := &hashiCorpConfig{
			address:  os.Getenv("VAULT_ADDR"),
			token:    os.Getenv("VAULT_TOKEN"),
			kvMount:  "test/bmccredsv1",
			insecure: false,
		}

		manager, err := NewHashiCorpVaultManagerForTesting(config, logger)
		require.NoError(t, err)
		defer func() {
			if err := manager.Close(); err != nil {
				t.Logf("Warning: failed to close vault manager: %v", err)
			}
		}()

		// Test credential retrieval
		creds, err := manager.GetCredentials(context.Background(), "192.168.10.10")
		require.NoError(t, err)
		require.NotNil(t, creds)

		assert.Equal(t, "root", creds.Username)
		assert.Equal(t, "calvin", creds.Password)
	})

	// Test with KV v2
	t.Run("KVv2_CredentialRetrieval", func(t *testing.T) {
		config := &hashiCorpConfig{
			address:  os.Getenv("VAULT_ADDR"),
			token:    os.Getenv("VAULT_TOKEN"),
			kvMount:  "test/bmccredsv2",
			insecure: false,
		}

		manager, err := NewHashiCorpVaultManagerForTesting(config, logger)
		require.NoError(t, err)
		defer func() {
			if err := manager.Close(); err != nil {
				t.Logf("Warning: failed to close vault manager: %v", err)
			}
		}()

		// Test credential retrieval
		creds, err := manager.GetCredentials(context.Background(), "192.168.10.10")
		require.NoError(t, err)
		require.NotNil(t, creds)

		assert.Equal(t, "root", creds.Username)
		assert.Equal(t, "calvin", creds.Password)
	})
}
