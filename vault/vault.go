package vault

import (
	"fmt"

	"github.com/asama-ai/redfish_exporter/vault/hashicorp"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	vaultType            string
	HashiCorpVaultClient *hashicorp.HashiCorpVaultClient
)

func AddFlags(a *kingpin.Application) {
	vaultType = *a.Flag("vault.type", "Specify the type of vault (default: none).").Enum(
		"hashiCorp",
		"aws",
		"azure",
		"google",
		"cyberArk",
		"lastPass",
		"bitwarden",
		"keePass",
		"thycotic")
	hashicorp.AddFlags(a)

	// Add for other vaults (e.g., AWS, GCP)

}
func GetCredentials(target string) (username string, password string, err error) {
	switch vaultType {
	case "hashiCorp":
		return hashicorp.GetCredentials(target)
	case "AWS", "Azure", "Google", "CyberArk", "LastPass", "Bitwarden", "KeePass", "Thycotic":
		return "", "", fmt.Errorf("vault type %q support not implemented yet", vaultType)
	// Add cases for other vaults (e.g., AWS, GCP)
	default:
		return "", "", fmt.Errorf("unsupported vault type: %s", vaultType)
	}
}

// VaultClient defines the interface for interacting with a vault to get credentials.
type VaultClient interface {
	GetCredentials(target string) (username string, password string, err error)
}

func GetVaultType() string {
	return vaultType
}

// NewVaultClient is a factory function that returns the appropriate VaultClient.
func NewVaultClient() error {
	switch vaultType {
	case "hashiCorp":
		return hashicorp.NewHashiCorpVaultClient()
	case "AWS", "Azure", "Google", "CyberArk", "LastPass", "Bitwarden", "KeePass", "Thycotic":
		return fmt.Errorf("vault type %q support not implemented yet", vaultType)
	// Add cases for other vaults (e.g., AWS, GCP)
	default:
		return fmt.Errorf("unsupported vault type: %s", vaultType)
	}
}
