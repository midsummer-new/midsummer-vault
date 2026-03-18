package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadCredentials(t *testing.T) {
	// Use a temp dir to avoid polluting the real config
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	creds := &Credentials{
		APIURL:       "https://test.midsummerai.com",
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		Email:        "test@example.com",
	}

	if err := SaveCredentials(creds); err != nil {
		t.Fatalf("SaveCredentials: %v", err)
	}

	// Verify file permissions
	path, _ := CredentialsPath()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 permissions, got %o", info.Mode().Perm())
	}

	loaded, err := LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil credentials")
	}
	if loaded.APIURL != creds.APIURL || loaded.AccessToken != creds.AccessToken {
		t.Error("loaded credentials don't match saved")
	}
}

func TestLoadCredentials_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	loaded, err := LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if loaded != nil {
		t.Error("expected nil for missing credentials")
	}
}

func TestDeleteCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	creds := &Credentials{
		APIURL:       "https://test.midsummerai.com",
		AccessToken:  "test",
		RefreshToken: "test",
		Email:        "test@example.com",
	}
	_ = SaveCredentials(creds)

	if err := DeleteCredentials(); err != nil {
		t.Fatalf("DeleteCredentials: %v", err)
	}

	path := filepath.Join(tmpDir, ".config", "midsummerai", "vault", "credentials.json")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected credentials file to be deleted")
	}
}
