package vault

import (
	"fmt"
	"strings"

	alog "github.com/apex/log"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

type RedfishCreds struct {
	Username string
	Password string
}

// VaultClient defines the interface for interacting with a vault to get credentials.
type VaultClient interface {
	GetCredentials(target string) (*RedfishCreds, error)
}

// VaultType represents the type of vault
type VaultType string

const (
	VaultTypeHashiCorp VaultType = "HashiCorp"
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

var (
	vaultType   *VaultType
	vaultClient VaultClient
	logger      *alog.Entry
)

// SetLogger sets the logger context for the vault package
func SetLogger(l *alog.Entry) {
	logger = l.WithField("driver", vaultType.String())
}

func AddFlags(a *kingpin.Application) {
	vaultType = new(VaultType)
	a.Flag("vault.type", "Specify the type of vault (only 'HashiCorp' is supported)").SetValue(vaultType)

	addHashiCorpFlags(a)
	// Add flags for other vaults
}

func GetCredentials(target string) (username string, password string, err error) {
	logger.Debugf("Getting credentials for target: %s", target)
	creds, err := vaultClient.GetCredentials(target)
	if err != nil {
		logger.Errorf("Failed to get credentials for target %s: %v", target, err)
		return "", "", err
	}
	logger.Debugf("Successfully retrieved credentials for target: %s", target)
	return creds.Username, creds.Password, nil
}

func Enabled() bool {
	enabled := vaultType != nil
	logger.Debugf("Vault enabled: %t", enabled)
	return enabled
}

// Initialize initilizes the configured VaultClient.
func Initialize() error {
	logger.Debug("Initializing vault client")

	if !Enabled() {
		logger.Debug("Vault is not enabled - no vault type specified")
		return fmt.Errorf("vault type not specified")
	}

	logger.Infof("Initializing vault client for type: %s", *vaultType)
	switch *vaultType {
	case VaultTypeHashiCorp:
		var err error
		vaultClient, err = NewHashiCorpVaultClient()
		if err != nil {
			logger.Errorf("Failed to initialize HashiCorp vault client: %v", err)
			return err
		}
		logger.Info("Vault client initialized successfully")
		return nil
	default:
		logger.Errorf("Unsupported vault type: %s", *vaultType)
		return fmt.Errorf("unsupported vault type: %s", *vaultType)
	}
}
