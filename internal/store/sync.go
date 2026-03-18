package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Reichel1/midsummer/vault-cli/internal/config"
)

const (
	syncTimeout     = 3 * time.Second
	hashCheckTimeout = 2 * time.Second
	defaultSyncURL  = "https://vault.midsummer.new"
)

// SyncConfig holds sync connection info for auto-sync operations.
type SyncConfig struct {
	APIURL    string
	ProjectID string
	Token     string // access token from credentials.json
	Enabled   bool
}

// LoadSyncConfig checks if sync is configured by looking at credentials, .vault.toml, and env vars.
// Returns config with Enabled=false if any piece is missing.
func LoadSyncConfig() SyncConfig {
	var cfg SyncConfig

	// resolve project ID: VAULT_PROJECT_ID env > .vault.toml
	cfg.ProjectID = os.Getenv("VAULT_PROJECT_ID")
	projectCfg, _ := config.LoadProjectConfig()
	if cfg.ProjectID == "" && projectCfg != nil {
		cfg.ProjectID = projectCfg.Vault.ProjectID
	}
	if cfg.ProjectID == "" {
		return cfg // no project linked
	}

	// resolve API URL: VAULT_API_URL env > .vault.toml api_url > default
	cfg.APIURL = os.Getenv("VAULT_API_URL")
	if cfg.APIURL == "" && projectCfg != nil && projectCfg.Vault.APIURL != "" {
		cfg.APIURL = projectCfg.Vault.APIURL
	}
	if cfg.APIURL == "" {
		cfg.APIURL = defaultSyncURL
	}

	// resolve access token from credentials.json
	creds, err := config.LoadCredentials()
	if err != nil || creds == nil || creds.AccessToken == "" {
		return cfg // not logged in
	}
	cfg.Token = creds.AccessToken

	cfg.Enabled = true
	return cfg
}

// syncPushRequest is the JSON body for push.
type syncPushRequest struct {
	Environment   string `json:"environment"`
	EncryptedBlob string `json:"encryptedBlob"`
	BlobHash      string `json:"blobHash"`
}

// syncPullResponse is the JSON body from pull.
type syncPullResponse struct {
	EncryptedBlob string `json:"encryptedBlob"`
	BlobHash      string `json:"blobHash"`
	UpdatedAt     string `json:"updatedAt"`
}

// syncHashResponse is the JSON body from hash check.
type syncHashResponse struct {
	BlobHash string `json:"blobHash"`
}

// Push uploads the local encrypted blob to the server.
// Non-fatal: returns error for caller to log as warning.
func Push(cfg SyncConfig, env string) error {
	s, err := OpenWithEnv(env)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	blob, err := os.ReadFile(s.SecretsPath())
	if err != nil {
		return fmt.Errorf("read blob: %w", err)
	}
	if len(blob) == 0 {
		return nil // nothing to push
	}

	hash := sha256.Sum256(blob)

	payload := syncPushRequest{
		Environment:   env,
		EncryptedBlob: string(blob),
		BlobHash:      hex.EncodeToString(hash[:]),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/vaults/%s/sync", cfg.APIURL, cfg.ProjectID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: syncTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// Pull downloads the latest blob from the server and writes it locally.
// Non-fatal: returns error for caller to log as warning.
func Pull(cfg SyncConfig, env string) error {
	s, err := OpenWithEnv(env)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/vaults/%s/sync?environment=%s", cfg.APIURL, cfg.ProjectID, env)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	client := &http.Client{Timeout: syncTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var pullResp syncPullResponse
	if err := json.NewDecoder(resp.Body).Decode(&pullResp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if pullResp.EncryptedBlob == "" {
		return nil // no remote blob yet
	}

	return os.WriteFile(s.SecretsPath(), []byte(pullResp.EncryptedBlob), 0600)
}

// NeedsPull checks if the local blob is outdated by comparing hashes with the server.
// Returns false on any error (timeout, unreachable, etc.) — safe to skip.
func NeedsPull(cfg SyncConfig, env string) bool {
	// compute local hash
	s, err := OpenWithEnv(env)
	if err != nil {
		return false
	}

	localBlob, err := os.ReadFile(s.SecretsPath())
	if err != nil {
		// no local file — pull is needed if server has something
		return needsPullNoLocal(cfg, env)
	}

	localHash := sha256.Sum256(localBlob)
	localHex := hex.EncodeToString(localHash[:])

	// fetch remote hash
	remoteHash, err := fetchRemoteHash(cfg, env)
	if err != nil || remoteHash == "" {
		return false // can't reach server or no remote blob
	}

	return localHex != remoteHash
}

// needsPullNoLocal checks if the server has a blob when there's no local file.
func needsPullNoLocal(cfg SyncConfig, env string) bool {
	remoteHash, err := fetchRemoteHash(cfg, env)
	if err != nil {
		return false
	}
	return remoteHash != ""
}

// fetchRemoteHash gets the blob hash from the server with a short timeout.
func fetchRemoteHash(cfg SyncConfig, env string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/vaults/%s/sync?environment=%s", cfg.APIURL, cfg.ProjectID, env)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	client := &http.Client{Timeout: hashCheckTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var hashResp syncPullResponse
	if err := json.NewDecoder(resp.Body).Decode(&hashResp); err != nil {
		return "", err
	}

	return hashResp.BlobHash, nil
}
