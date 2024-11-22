package vault

import (
	"bytes"
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

// HashiCorpVaultClient implements the VaultClient interface for HashiCorp Vault.
type HashiCorpVaultClient struct {
	client *api.Client
}

var secretPath *string

// Adds the Hashicorp Flags
func addHashiCorpFlags(a *kingpin.Application) {
	vaultAddress = a.Flag("ip", "IP address of the Vault").Default("http://127.0.0.1:8200").String()
	tokenFile = a.Flag("token-file", "Path to the file containing the Vault token").String()
	secretPath = a.Flag("secret-path", "Path to the secret in the Vault").Default("redfish/creds/data/").String()
}

// NewHashiCorpVaultClient creates a new Vault client for HashiCorp Vault.
func NewHashiCorpVaultClient(vaultAddress, tokenFile string) (VaultClient, error) {

	if tokenFile == "" {
		return nil, fmt.Errorf("--token-file is required when using hashicorp vault")
	}

	// Read the token from the specified file
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}

	// Convert byte slices to strings and trim whitespace
	vaultToken := string(bytes.TrimSpace(token))

	config := api.DefaultConfig()
	config.Address = vaultAddress

	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}

	client.SetToken(vaultToken)
	return &HashiCorpVaultClient{client: client}, nil
}

// GetCredentials retrieves credentials from HashiCorp Vault.
func (h *HashiCorpVaultClient) GetCredentials(target string) (string, string, error) {
	vaultPath := fmt.Sprint(*secretPath + target)
	secret, err := h.client.Logical().Read(vaultPath)
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
