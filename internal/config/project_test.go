package config

import (
	"os"
	"testing"
)

func TestLoadProjectConfig_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	content := `[vault]
project_id = "abc123def456"
api_url = "https://custom-api.example.com"
`
	os.WriteFile(".vault.toml", []byte(content), 0644)

	cfg, err := LoadProjectConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Vault.ProjectID != "abc123def456" {
		t.Errorf("unexpected project_id: %s", cfg.Vault.ProjectID)
	}
	if cfg.Vault.APIURL != "https://custom-api.example.com" {
		t.Errorf("unexpected api_url: %s", cfg.Vault.APIURL)
	}
}

func TestLoadProjectConfig_MinimalFile(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	content := `[vault]
project_id = "proj_minimal"
`
	os.WriteFile(".vault.toml", []byte(content), 0644)

	cfg, err := LoadProjectConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Vault.ProjectID != "proj_minimal" {
		t.Errorf("unexpected project_id: %s", cfg.Vault.ProjectID)
	}
	if cfg.Vault.APIURL != "" {
		t.Errorf("expected empty api_url, got: %s", cfg.Vault.APIURL)
	}
}

func TestLoadProjectConfig_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	cfg, err := LoadProjectConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Error("expected nil config when file doesn't exist")
	}
}

func TestLoadProjectConfig_InvalidTOML(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	os.WriteFile(".vault.toml", []byte("{{invalid toml"), 0644)

	_, err := LoadProjectConfig()
	if err == nil {
		t.Error("expected error for invalid TOML")
	}
}

func TestLoadProjectConfig_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	os.WriteFile(".vault.toml", []byte(""), 0644)

	cfg, err := LoadProjectConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config for empty file")
	}
	if cfg.Vault.ProjectID != "" {
		t.Errorf("expected empty project_id, got: %s", cfg.Vault.ProjectID)
	}
}
