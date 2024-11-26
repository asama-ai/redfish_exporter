package hashicorp

import (
	"bytes"
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var HashiCorpClient HashiCorpVaultClient

// HashiCorpVaultClient implements the VaultClient interface for HashiCorp Vault.
type HashiCorpVaultClient struct {
	client       *api.Client
	secretPath   *string
	tokenFile    *string
	vaultAddress *string
}

// Adds the Hashicorp Flags
func AddFlags(a *kingpin.Application) {
	HashiCorpClient.vaultAddress = a.Flag("ip", "IP address of tCliente Vault").Default("http://127.0.0.1:8200").String()
	HashiCorpClient.tokenFile = a.Flag("token-file", "Path to the file containing the Vault token").String()
	HashiCorpClient.secretPath = a.Flag("secret-path", "Path to the secret in the Vault").Default("redfish/creds/data/").String()
}

// NewHashiCorpVaultClient creates a new Vault client for HashiCorp Vault.
func NewHashiCorpVaultClient() error {

	if HashiCorpClient.tokenFile == nil {
		return fmt.Errorf("--token-file is required when using hashicorp vault")
	}

	// Read the token from the specified file
	token, err := os.ReadFile(*HashiCorpClient.tokenFile)
	if err != nil {
		return err
	}

	// Convert byte slices to strings and trim whitespace
	vaultToken := string(bytes.TrimSpace(token))
	if vaultToken == "" {
		return fmt.Errorf("vault token is empty; please ensure the token file contains a valid token")
	}

	config := api.DefaultConfig()
	config.Address = *HashiCorpClient.vaultAddress

	client, err := api.NewClient(config)
	if err != nil {
		return err
	}

	client.SetToken(vaultToken)
	_, err = client.Auth().Token().LookupSelf()
	if err != nil {
		return fmt.Errorf("invalid vault token: %v", err)
	}
	HashiCorpClient.client = client
	return nil
}

// GetCredentials retrieves credentials from HashiCorp Vault.
func GetCredentials(target string) (string, string, error) {
	vaultPath := fmt.Sprint(*HashiCorpClient.secretPath + target)
	secret, err := HashiCorpClient.client.Logical().Read(vaultPath)
	if err != nil {
		return "", "", err
	}

	if secret == nil || secret.Data == nil {
		return "", "", fmt.Errorf("no data found for target %s", target)
	}
	dataInterface, ok := secret.Data["data"]
	if !ok {
		return "", "", fmt.Errorf("data not found for target %s", target)
	}
	data, ok := dataInterface.(map[string]interface{})
	if !ok {
		return "", "", fmt.Errorf("unexpected data format for target %s", target)
	}
	username, ok := data["username"].(string)
	if !ok {
		return "", "", fmt.Errorf("username not found for target %s", target)
	}

	password, ok := data["password"].(string)
	if !ok {
		return "", "", fmt.Errorf("password not found for target %s", target)
	}
	return username, password, nil
}
