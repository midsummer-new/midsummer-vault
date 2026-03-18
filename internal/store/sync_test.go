package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSyncConfigDisabledWithoutProjectID(t *testing.T) {
	// clear env vars that could affect config
	t.Setenv("VAULT_PROJECT_ID", "")
	t.Setenv("VAULT_API_URL", "")

	// no .vault.toml in cwd, no env vars — should be disabled
	origDir, _ := os.Getwd()
	tmp := t.TempDir()
	os.Chdir(tmp)
	defer os.Chdir(origDir)

	cfg := LoadSyncConfig()
	if cfg.Enabled {
		t.Fatal("sync should be disabled without project ID")
	}
}

func TestLoadSyncConfigDisabledWithoutCredentials(t *testing.T) {
	t.Setenv("VAULT_PROJECT_ID", "proj_123")
	t.Setenv("VAULT_API_URL", "https://example.com")

	// override HOME to a temp dir so credentials.json won't be found
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	cfg := LoadSyncConfig()
	if cfg.Enabled {
		t.Fatal("sync should be disabled without credentials")
	}
	if cfg.ProjectID != "proj_123" {
		t.Fatalf("ProjectID should be proj_123, got %q", cfg.ProjectID)
	}
}

func TestLoadSyncConfigEnabledFromEnv(t *testing.T) {
	t.Setenv("VAULT_PROJECT_ID", "proj_abc")
	t.Setenv("VAULT_API_URL", "https://vault.test.com")

	// create credentials.json
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	credsDir := filepath.Join(tmpHome, ".config", "midsummerai", "vault")
	os.MkdirAll(credsDir, 0700)
	creds := map[string]string{
		"api_url":       "https://vault.test.com",
		"access_token":  "test-token-123",
		"refresh_token": "refresh-456",
		"email":         "test@example.com",
	}
	data, _ := json.Marshal(creds)
	os.WriteFile(filepath.Join(credsDir, "credentials.json"), data, 0600)

	cfg := LoadSyncConfig()
	if !cfg.Enabled {
		t.Fatal("sync should be enabled with project ID + credentials")
	}
	if cfg.ProjectID != "proj_abc" {
		t.Fatalf("ProjectID = %q, want proj_abc", cfg.ProjectID)
	}
	if cfg.APIURL != "https://vault.test.com" {
		t.Fatalf("APIURL = %q, want https://vault.test.com", cfg.APIURL)
	}
	if cfg.Token != "test-token-123" {
		t.Fatalf("Token = %q, want test-token-123", cfg.Token)
	}
}

func TestLoadSyncConfigDefaultURL(t *testing.T) {
	t.Setenv("VAULT_PROJECT_ID", "proj_def")
	t.Setenv("VAULT_API_URL", "")

	// no .vault.toml in cwd
	origDir, _ := os.Getwd()
	tmp := t.TempDir()
	os.Chdir(tmp)
	defer os.Chdir(origDir)

	// create credentials
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	credsDir := filepath.Join(tmpHome, ".config", "midsummerai", "vault")
	os.MkdirAll(credsDir, 0700)
	creds := map[string]string{
		"access_token": "tok",
	}
	data, _ := json.Marshal(creds)
	os.WriteFile(filepath.Join(credsDir, "credentials.json"), data, 0600)

	cfg := LoadSyncConfig()
	if !cfg.Enabled {
		t.Fatal("sync should be enabled")
	}
	if cfg.APIURL != defaultSyncURL {
		t.Fatalf("APIURL = %q, want default %q", cfg.APIURL, defaultSyncURL)
	}
}

func TestPushSuccess(t *testing.T) {
	// create a local vault with a secret
	s := testStore(t)
	s.Set("API_KEY", "secret_value")

	// mock server that accepts push
	var receivedBody syncPushRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("wrong auth header: %s", r.Header.Get("Authorization"))
		}

		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := SyncConfig{
		APIURL:    server.URL,
		ProjectID: "proj_test",
		Token:     "test-token",
		Enabled:   true,
	}

	// Push needs to find the vault by walking up from cwd
	origDir, _ := os.Getwd()
	// change to the dir containing .vault
	os.Chdir(filepath.Dir(s.dir))
	defer os.Chdir(origDir)

	err := Push(cfg, DefaultEnv)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	if receivedBody.Environment != DefaultEnv {
		t.Fatalf("expected environment %q, got %q", DefaultEnv, receivedBody.Environment)
	}
	if receivedBody.EncryptedBlob == "" {
		t.Fatal("expected non-empty blob")
	}
	if receivedBody.BlobHash == "" {
		t.Fatal("expected non-empty hash")
	}

	// verify hash matches the blob
	hash := sha256.Sum256([]byte(receivedBody.EncryptedBlob))
	expectedHash := hex.EncodeToString(hash[:])
	if receivedBody.BlobHash != expectedHash {
		t.Fatalf("hash mismatch: got %s, want %s", receivedBody.BlobHash, expectedHash)
	}
}

func TestPushServerError(t *testing.T) {
	s := testStore(t)
	s.Set("KEY", "val")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	cfg := SyncConfig{
		APIURL:    server.URL,
		ProjectID: "proj_test",
		Token:     "test-token",
		Enabled:   true,
	}

	origDir, _ := os.Getwd()
	os.Chdir(filepath.Dir(s.dir))
	defer os.Chdir(origDir)

	err := Push(cfg, DefaultEnv)
	if err == nil {
		t.Fatal("expected error on server error")
	}
}

func TestPullSuccess(t *testing.T) {
	s := testStore(t)
	// set a secret so the encrypted blob format is correct
	s.Set("ORIGINAL", "val")

	// read the blob to serve it from mock
	blob, _ := os.ReadFile(s.SecretsPath())
	hash := sha256.Sum256(blob)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		resp := syncPullResponse{
			EncryptedBlob: string(blob),
			BlobHash:      hex.EncodeToString(hash[:]),
			UpdatedAt:     "2026-03-17T00:00:00Z",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := SyncConfig{
		APIURL:    server.URL,
		ProjectID: "proj_test",
		Token:     "test-token",
		Enabled:   true,
	}

	origDir, _ := os.Getwd()
	os.Chdir(filepath.Dir(s.dir))
	defer os.Chdir(origDir)

	err := Pull(cfg, DefaultEnv)
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}

	// verify the blob was written
	written, _ := os.ReadFile(s.SecretsPath())
	if string(written) != string(blob) {
		t.Fatal("pulled blob doesn't match server blob")
	}
}

func TestPullEmptyBlob(t *testing.T) {
	s := testStore(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := syncPullResponse{EncryptedBlob: "", BlobHash: "", UpdatedAt: ""}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := SyncConfig{
		APIURL:    server.URL,
		ProjectID: "proj_test",
		Token:     "test-token",
		Enabled:   true,
	}

	origDir, _ := os.Getwd()
	os.Chdir(filepath.Dir(s.dir))
	defer os.Chdir(origDir)

	err := Pull(cfg, DefaultEnv)
	if err != nil {
		t.Fatalf("Pull with empty blob should not error: %v", err)
	}
}

func TestNeedsPullSameHash(t *testing.T) {
	s := testStore(t)
	s.Set("KEY", "val")

	blob, _ := os.ReadFile(s.SecretsPath())
	hash := sha256.Sum256(blob)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := syncPullResponse{
			EncryptedBlob: string(blob),
			BlobHash:      hex.EncodeToString(hash[:]),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := SyncConfig{
		APIURL:    server.URL,
		ProjectID: "proj_test",
		Token:     "test-token",
		Enabled:   true,
	}

	origDir, _ := os.Getwd()
	os.Chdir(filepath.Dir(s.dir))
	defer os.Chdir(origDir)

	if NeedsPull(cfg, DefaultEnv) {
		t.Fatal("NeedsPull should be false when hashes match")
	}
}

func TestNeedsPullDifferentHash(t *testing.T) {
	s := testStore(t)
	s.Set("KEY", "val")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := syncPullResponse{
			EncryptedBlob: "different-blob",
			BlobHash:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := SyncConfig{
		APIURL:    server.URL,
		ProjectID: "proj_test",
		Token:     "test-token",
		Enabled:   true,
	}

	origDir, _ := os.Getwd()
	os.Chdir(filepath.Dir(s.dir))
	defer os.Chdir(origDir)

	if !NeedsPull(cfg, DefaultEnv) {
		t.Fatal("NeedsPull should be true when hashes differ")
	}
}

func TestNeedsPullServerUnreachable(t *testing.T) {
	s := testStore(t)
	s.Set("KEY", "val")

	cfg := SyncConfig{
		APIURL:    "http://127.0.0.1:1", // unreachable
		ProjectID: "proj_test",
		Token:     "test-token",
		Enabled:   true,
	}

	origDir, _ := os.Getwd()
	os.Chdir(filepath.Dir(s.dir))
	defer os.Chdir(origDir)

	// should return false, not panic or block
	if NeedsPull(cfg, DefaultEnv) {
		t.Fatal("NeedsPull should be false when server is unreachable")
	}
}

func TestNeedsPullNoLocalFile(t *testing.T) {
	// create vault dir but no secrets file
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, ".vault")
	os.MkdirAll(vaultPath, 0700)

	os.WriteFile(filepath.Join(vaultPath, "key"), []byte("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"), 0600)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := syncPullResponse{
			EncryptedBlob: "some-blob",
			BlobHash:      "deadbeef",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := SyncConfig{
		APIURL:    server.URL,
		ProjectID: "proj_test",
		Token:     "test-token",
		Enabled:   true,
	}

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	// server has a blob, local doesn't — should need pull
	if !NeedsPull(cfg, DefaultEnv) {
		t.Fatal("NeedsPull should be true when local file is missing but server has blob")
	}
}
