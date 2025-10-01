package vault

import (
	"context"
	"os"
	"testing"

	alog "github.com/apex/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// func init() {
// 	// Configure apex logger for test debugging
// 	alog.SetLevel(alog.DebugLevel)
// }

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

// TestHashiCorpVaultIntegration tests real HashiCorp Vault connections for both KV v1 and v2
func TestHashiCorpVaultIntegration(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("VAULT_ADDR") == "" || os.Getenv("VAULT_TOKEN") == "" {
		t.Skip("Skipping integration test: VAULT_ADDR and VAULT_TOKEN environment variables not set")
	}

	// Test data
	target := "192.168.10.10"
	expectedUsername := "root"
	expectedPassword := "calvin"

	// Create logger
	logger := alog.WithField("test", "integration")

	tests := []struct {
		name      string
		mountPath string
	}{
		{
			name:      "KV v1 integration test",
			mountPath: "test/bmccredsv1",
		},
		{
			name:      "KV v1 integration test with trailing slash",
			mountPath: "test/bmccredsv1/",
		},
		{
			name:      "KV v2 integration test",
			mountPath: "test/bmccredsv2",
		},
		{
			name:      "KV v2 integration test with trailing slash",
			mountPath: "test/bmccredsv2/",
		},
	}

	for _, tt := range tests {
		tt := tt
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
			t.Cleanup(func() {
				if err := manager.Close(); err != nil {
					t.Logf("Warning: failed to close vault manager: %v", err)
				}
			})

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

		})
	}
}

// TestHashiCorpVaultIntegrationErrorHandling tests HashiCorp Vault error scenarios
func TestHashiCorpVaultIntegrationErrorHandling(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("VAULT_ADDR") == "" || os.Getenv("VAULT_TOKEN") == "" {
		t.Skip("Skipping integration test: VAULT_ADDR and VAULT_TOKEN environment variables not set")
	}

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
			expectError: false, // Initialization will succeed, error occurs during credential retrieval
			errorMsg:    "",    // Not applicable since we expect success
		},
		{
			name: "Invalid token",
			config: &hashiCorpConfig{
				address:  os.Getenv("VAULT_ADDR"),
				token:    "invalid-token",
				kvMount:  "test/bmccredsv1",
				insecure: false,
			},
			expectError: false, // Initialization will succeed, error occurs during health check
			errorMsg:    "",    // Not applicable since we expect success
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewHashiCorpVaultManagerForTesting(tt.config, logger)

			if tt.expectError {
				assert.Error(t, err, "Expected error for invalid configuration")
				if err != nil {
					assert.Contains(t, err.Error(), tt.errorMsg, "Error message should contain expected text")
				}
				assert.Nil(t, manager, "Manager should be nil on error")
			} else {
				assert.NoError(t, err, "Should not error with valid configuration")
				assert.NotNil(t, manager, "Manager should not be nil")

				// Cleanup if manager was created successfully
				if manager != nil {
					t.Cleanup(func() {
						if err := manager.Close(); err != nil {
							t.Logf("Warning: failed to close vault manager: %v", err)
						}
					})
				}

				// For invalid mount path, test that credential retrieval fails
				if tt.name == "Invalid mount path" {
					_, err := manager.GetCredentials(context.Background(), "192.168.10.10")
					assert.Error(t, err, "Expected error when trying to get credentials from invalid mount path")
					assert.Contains(t, err.Error(), "failed to retrieve secret", "Error should indicate secret retrieval failure")
				}

				// For invalid token, test that health check fails
				if tt.name == "Invalid token" {
					err := manager.HealthCheck(context.Background())
					assert.Error(t, err, "Expected error when trying to perform health check with invalid token")
					assert.Contains(t, err.Error(), "vault health check failed", "Error should indicate health check failure")
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
		t.Cleanup(func() {
			if err := manager.Close(); err != nil {
				t.Logf("Warning: failed to close vault manager: %v", err)
			}
		})

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
		t.Cleanup(func() {
			if err := manager.Close(); err != nil {
				t.Logf("Warning: failed to close vault manager: %v", err)
			}
		})

		// Test credential retrieval
		creds, err := manager.GetCredentials(context.Background(), "192.168.10.10")
		require.NoError(t, err)
		require.NotNil(t, creds)

		assert.Equal(t, "root", creds.Username)
		assert.Equal(t, "calvin", creds.Password)
	})
}
