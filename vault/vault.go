package vault

import (
	"fmt"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	vaultAddress *string
	vaultType    *string
)

func AddFlags(a *kingpin.Application) {
	vaultType = (a.Flag("vault.type", "Specify the type of vault (default: none).").Required().Enum(
		"hashiCorp",
		"aws",
		"azure",
		"google",
		"cyberArk",
		"lastPass",
		"bitwarden",
		"keePass",
		"thycotic"))
	addHashiCorpFlags(a)
	// Add for other vaults (e.g., AWS, GCP)

}

// VaultClient defines the interface for interacting with a vault to get credentials.
type VaultClient interface {
	GetCredentials(target string) (username string, password string, err error)
}

func GetVaultType() string {
	return *vaultType
}

// NewVaultClient is a factory function that returns the appropriate VaultClient.
func NewVaultClient() (VaultClient, error) {
	switch *vaultType {
	case "hashiCorp":
		return NewHashiCorpVaultClient(*vaultAddress, *tokenFile)
	case "AWS", "Azure", "Google", "CyberArk", "LastPass", "Bitwarden", "KeePass", "Thycotic":
		return nil, fmt.Errorf("vault type %q support not implemented yet", *vaultType)
	// Add cases for other vaults (e.g., AWS, GCP)
	default:
		return nil, fmt.Errorf("unsupported vault type: %s", *vaultType)
	}
}
