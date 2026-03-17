package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Reichel1/midsummer/vault-cli/internal/auth"
	"github.com/Reichel1/midsummer/vault-cli/internal/config"
)

// Client communicates with the Midsummer AI API.
type Client struct {
	apiURL     string
	httpClient *http.Client
	creds      *config.Credentials
}

// NewClient creates an API client, refreshing the token if needed.
func NewClient(creds *config.Credentials) (*Client, error) {
	c := &Client{
		apiURL:     creds.APIURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		creds:      creds,
	}

	// Auto-refresh if access token is expired
	if auth.IsTokenExpired(creds.AccessToken) {
		if err := c.RefreshTokens(); err != nil {
			return nil, fmt.Errorf("token expired, run `vault login` to re-authenticate: %w", err)
		}
	}

	return c, nil
}

// NewClientDirect creates an API client without token refresh.
// Used for service tokens which are short-lived and non-refreshable.
func NewClientDirect(creds *config.Credentials) (*Client, error) {
	return &Client{
		apiURL:     creds.APIURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		creds:      creds,
	}, nil
}

// GetSecrets fetches decrypted secrets for a project.
func (c *Client) GetSecrets(projectID string) (map[string]string, error) {
	url := fmt.Sprintf("%s/api/vault/%s/secrets", c.apiURL, projectID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.creds.AccessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Secrets map[string]string `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Secrets, nil
}

// GetSecretNames fetches just the secret names for a project.
func (c *Client) GetSecretNames(projectID string) ([]string, error) {
	url := fmt.Sprintf("%s/api/vault/%s/secrets?names_only=true", c.apiURL, projectID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.creds.AccessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Names []string `json:"names"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Names, nil
}

// RefreshTokens calls POST /api/auth/token to get a new token pair.
func (c *Client) RefreshTokens() error {
	body := fmt.Sprintf(`{"refreshToken":"%s"}`, c.creds.RefreshToken)
	resp, err := c.httpClient.Post(
		c.apiURL+"/api/auth/token",
		"application/json",
		strings.NewReader(body),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("token refresh failed (status %d)", resp.StatusCode)
	}

	var result struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	c.creds.AccessToken = result.AccessToken
	c.creds.RefreshToken = result.RefreshToken

	// Persist updated tokens
	return config.SaveCredentials(c.creds)
}
