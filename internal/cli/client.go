package cli

import (
	"fmt"
	"os"

	vaultapi "github.com/Reichel1/midsummer/vault-cli/internal/api"
	"github.com/Reichel1/midsummer/vault-cli/internal/config"
)

// clientResult holds an API client and the project ID to use.
type clientResult struct {
	client    *vaultapi.Client
	projectID string
}

// getClientAndProject returns an API client and project ID.
// Priority: VAULT_SERVICE_TOKEN env (sandbox) > credentials.json + .vault.toml (local dev).
func getClientAndProject() (*clientResult, error) {
	// 1. Service token mode (headless sandbox)
	serviceToken := os.Getenv("VAULT_SERVICE_TOKEN")
	projectID := os.Getenv("VAULT_PROJECT_ID")
	apiURL := os.Getenv("VAULT_API_URL")

	if serviceToken != "" && projectID != "" {
		if apiURL == "" {
			apiURL = defaultAPIURL
		}
		creds := &config.Credentials{
			APIURL:      apiURL,
			AccessToken: serviceToken,
		}
		client, err := vaultapi.NewClientDirect(creds)
		if err != nil {
			return nil, fmt.Errorf("service token auth error: %w", err)
		}
		return &clientResult{client: client, projectID: projectID}, nil
	}

	// 2. Standard flow: .vault.toml + credentials.json
	projectCfg, err := config.LoadProjectConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to read .vault.toml: %w", err)
	}
	if projectCfg == nil {
		return nil, fmt.Errorf("no .vault.toml found — run `vault init` or create one manually")
	}

	creds, err := config.LoadCredentials()
	if err != nil || creds == nil {
		return nil, fmt.Errorf("not logged in — run `vault login` first")
	}

	if projectCfg.Vault.APIURL != "" {
		creds.APIURL = projectCfg.Vault.APIURL
	}

	client, err := vaultapi.NewClient(creds)
	if err != nil {
		return nil, fmt.Errorf("auth error: %w", err)
	}

	return &clientResult{client: client, projectID: projectCfg.Vault.ProjectID}, nil
}
