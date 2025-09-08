package hashicorp

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/vault/api"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var HashiCorpClient HashiCorpVaultClient

type HashiCorpVaultClient struct {
	client             *api.Client
	secretPath         *string
	token              *string
	vaultAddress       *string
	insecureSkipVerify *bool
}

func AddFlags(a *kingpin.Application) {
	HashiCorpClient.vaultAddress = a.Flag("ip", "IP address of the Vault").Default("http://127.0.0.1:8200").String()
	HashiCorpClient.token = a.Flag("token", "Vault token (can also be set via VAULT_TOKEN environment variable)").String()
	HashiCorpClient.secretPath = a.Flag("secret-path", "Path to the secret in the Vault").Default("redfish/creds/data/").String()
	HashiCorpClient.insecureSkipVerify = a.Flag("insecure-skip-tls-verify", "Disable TLS verification (insecure, use for testing only)").Bool()
}

func NewHashiCorpVaultClient() error {
	var vaultToken string

	// Priority order: command line flag -> environment variable
	if HashiCorpClient.token != nil && *HashiCorpClient.token != "" {
		vaultToken = *HashiCorpClient.token
	} else if envToken := os.Getenv("VAULT_TOKEN"); envToken != "" {
		vaultToken = envToken
	} else {
		return fmt.Errorf("vault token is required: provide via --token flag or VAULT_TOKEN environment variable")
	}

	if vaultToken == "" {
		return fmt.Errorf("vault token is empty; please ensure a valid token is provided")
	}

	config := api.DefaultConfig()
	config.Address = *HashiCorpClient.vaultAddress

	// 🔑 Inject TLS settings if requested
	if HashiCorpClient.insecureSkipVerify != nil && *HashiCorpClient.insecureSkipVerify {
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		config.HttpClient.Transport = transport
	}

	client, err := api.NewClient(config)
	if err != nil {
		return err
	}

	client.SetToken(vaultToken)
	if _, err = client.Auth().Token().LookupSelf(); err != nil {
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
