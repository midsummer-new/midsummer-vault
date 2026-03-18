package cli

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

	"github.com/midsummer-new/midsummer-vault/internal/config"
	"github.com/midsummer-new/midsummer-vault/internal/store"
	"github.com/spf13/cobra"
)

// sync API request/response types

type syncPushRequest struct {
	Environment   string `json:"environment"`
	EncryptedBlob string `json:"encryptedBlob"`
	BlobHash      string `json:"blobHash"`
}

type syncPullResponse struct {
	EncryptedBlob string `json:"encryptedBlob"`
	BlobHash      string `json:"blobHash"`
	UpdatedAt     string `json:"updatedAt"`
}

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync encrypted vault blobs with vault.midsummer.new",
	Long: `Push and pull encrypted vault blobs to a remote server.
The server stores the blob as-is (zero knowledge — it never sees your key).

Commands:
  vault sync push             Push local encrypted blob to server
  vault sync pull             Pull encrypted blob from server
  vault sync push --env prod  Push production secrets`,
}

var syncPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push encrypted vault blob to the remote server",
	RunE: func(cmd *cobra.Command, args []string) error {
		apiURL, _, token, _ := resolveSyncConfig()
		if apiURL == "" || token == "" {
			fmt.Println("vault sync is coming soon. For now, vault works fully locally.")
			return nil
		}
		_ = apiURL
		_ = token

		env, _ := cmd.Flags().GetString("env")

		s, err := store.OpenWithEnv(env)
		if err != nil {
			return err
		}

		// read the raw encrypted blob
		blob, err := os.ReadFile(s.SecretsPath())
		if err != nil {
			return fmt.Errorf("read vault blob: %w", err)
		}

		if len(blob) == 0 {
			return fmt.Errorf("vault is empty — nothing to push")
		}

		// compute SHA-256 of the blob
		hash := sha256.Sum256(blob)
		blobHash := hex.EncodeToString(hash[:])

		syncURL, projectID, token, err := resolveSyncConfig()
		if err != nil {
			return err
		}

		payload := syncPushRequest{
			Environment:   env,
			EncryptedBlob: string(blob),
			BlobHash:      blobHash,
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}

		url := fmt.Sprintf("%s/api/v1/vaults/%s/sync", syncURL, projectID)
		req, err := http.NewRequest("POST", url, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("sync push request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			respBody, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("sync push failed (HTTP %d): %s", resp.StatusCode, string(respBody))
		}

		fmt.Printf("✓ Pushed %s vault to remote (hash: %s…)\n", env, blobHash[:12])
		return nil
	},
}

var syncPullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Pull encrypted vault blob from the remote server",
	RunE: func(cmd *cobra.Command, args []string) error {
		env, _ := cmd.Flags().GetString("env")

		s, err := store.OpenWithEnv(env)
		if err != nil {
			return err
		}

		syncURL, projectID, token, err := resolveSyncConfig()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/api/v1/vaults/%s/sync?environment=%s", syncURL, projectID, env)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("sync pull request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("sync pull failed (HTTP %d): %s", resp.StatusCode, string(respBody))
		}

		var pullResp syncPullResponse
		if err := json.NewDecoder(resp.Body).Decode(&pullResp); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}

		if pullResp.EncryptedBlob == "" {
			return fmt.Errorf("server returned empty blob — no secrets synced for %s", env)
		}

		// write the blob to the env-specific secrets file
		if err := os.WriteFile(s.SecretsPath(), []byte(pullResp.EncryptedBlob), 0600); err != nil {
			return fmt.Errorf("write vault blob: %w", err)
		}

		fmt.Printf("✓ Pulled %s vault from remote (hash: %s…, updated: %s)\n",
			env, pullResp.BlobHash[:min(12, len(pullResp.BlobHash))], pullResp.UpdatedAt)
		return nil
	},
}

// resolveSyncConfig returns (syncURL, projectID, accessToken, error).
// Priority: env vars > .vault.toml > default URL.
func resolveSyncConfig() (string, string, string, error) {
	// sync URL: VAULT_API_URL env > .vault.toml api_url > default
	syncURL := os.Getenv("VAULT_API_URL")
	if syncURL == "" {
		projectCfg, _ := config.LoadProjectConfig()
		if projectCfg != nil && projectCfg.Vault.APIURL != "" {
			syncURL = projectCfg.Vault.APIURL
		}
	}
	if syncURL == "" {
		syncURL = "https://vault.midsummer.new"
	}

	// project ID from .vault.toml or VAULT_PROJECT_ID env
	projectID := os.Getenv("VAULT_PROJECT_ID")
	if projectID == "" {
		projectCfg, _ := config.LoadProjectConfig()
		if projectCfg != nil {
			projectID = projectCfg.Vault.ProjectID
		}
	}
	if projectID == "" {
		return "", "", "", fmt.Errorf("no project ID — set VAULT_PROJECT_ID or add project_id to .vault.toml")
	}

	// access token from credentials.json
	creds, err := config.LoadCredentials()
	if err != nil || creds == nil || creds.AccessToken == "" {
		return "", "", "", fmt.Errorf("not logged in — run `vault login` first")
	}

	return syncURL, projectID, creds.AccessToken, nil
}

func init() {
	syncPushCmd.Flags().String("env", store.DefaultEnv, "Environment to push (development, staging, production)")
	syncPullCmd.Flags().String("env", store.DefaultEnv, "Environment to pull (development, staging, production)")

	syncCmd.AddCommand(syncPushCmd)
	syncCmd.AddCommand(syncPullCmd)
}
