package vault

import (
	"context"
	"fmt"
	"strings"
	"time"

	alog "github.com/apex/log"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

// RedfishCreds represents credentials for Redfish authentication
type RedfishCreds struct {
	Username string
	Password string
}

// VaultClient defines the interface for interacting with a vault to get credentials.
type VaultClient interface {
	GetCredentials(ctx context.Context, target string) (*RedfishCreds, error)
	HealthCheck(ctx context.Context) error
	Close() error
}

// VaultType represents the type of vault
type VaultType string

const (
	VaultTypeHashiCorp VaultType = "HashiCorp"
)

// Global variable for vault type flag
var (
	vaultTypeFlag *VaultType
)

// String returns the string representation of VaultType
func (v VaultType) String() string {
	return string(v)
}

// Set implements the kingpin.Value interface
func (v *VaultType) Set(value string) error {
	switch strings.ToLower(value) {
	case "hashicorp":
		*v = VaultTypeHashiCorp
	default:
		return fmt.Errorf("invalid vault type: %s (only 'HashiCorp' is supported)", value)
	}
	return nil
}

// VaultConfig holds configuration for vault clients
type VaultConfig struct {
	Type VaultType
	// HashiCorp-specific config is handled internally by the HashiCorp client
}

// VaultManager manages vault operations and provides a clean interface
type VaultManager struct {
	client VaultClient
	logger *alog.Entry
	config *VaultConfig
}

// NewVaultManager creates a new vault manager with the given configuration
func NewVaultManager(config *VaultConfig, logger *alog.Entry) (*VaultManager, error) {
	if config == nil {
		return nil, fmt.Errorf("vault config cannot be nil")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	switch config.Type {
	case VaultTypeHashiCorp:
		// Use HashiCorp-specific factory function that handles internal configuration
		return NewHashiCorpVaultManager(logger.WithField("component", "vault").WithField("type", config.Type.String()))
	default:
		return nil, fmt.Errorf("unsupported vault type: %s", config.Type)
	}
}

// GetCredentials retrieves credentials for the given target
func (vm *VaultManager) GetCredentials(ctx context.Context, target string) (*RedfishCreds, error) {
	vm.logger.Debugf("Getting credentials for target: %s", target)

	// Add 5-second timeout to the context
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	creds, err := vm.client.GetCredentials(ctx, target)
	if err != nil {
		vm.logger.Errorf("Failed to get credentials for target %s: %v", target, err)
		return nil, fmt.Errorf("failed to get credentials for target %s: %w", target, err)
	}

	vm.logger.Debugf("Successfully retrieved credentials for target: %s", target)
	return creds, nil
}

// HealthCheck performs a health check on the vault client
func (vm *VaultManager) HealthCheck(ctx context.Context) error {
	return vm.client.HealthCheck(ctx)
}

// Close closes the vault client
func (vm *VaultManager) Close() error {
	if vm.client != nil {
		return vm.client.Close()
	}
	return nil
}

// AddVaultFlags adds the vault type command line flag
func AddVaultFlags(a *kingpin.Application) {
	vaultTypeFlag = new(VaultType)
	a.Flag("vault.type", "Type of vault to use (hashicorp)").SetValue(vaultTypeFlag)

	addHashiCorpFlags(a)
}

// GetVaultType returns the vault type from the command line flag
func GetVaultType() VaultType {
	if vaultTypeFlag != nil {
		return *vaultTypeFlag
	}
	return ""
}

// IsVaultEnabled returns true if vault is enabled (vault type is set)
func IsVaultEnabled() bool {
	return GetVaultType() != ""
}
