package config

import (
	"errors"
	"os"

	"github.com/BurntSushi/toml"
)

// ProjectConfig represents .vault.toml.
type ProjectConfig struct {
	Vault VaultSection `toml:"vault"`
}

// VaultSection is the [vault] table in .vault.toml.
type VaultSection struct {
	ProjectID string `toml:"project_id"`
	APIURL    string `toml:"api_url"`
}

// LoadProjectConfig reads .vault.toml from the current directory.
func LoadProjectConfig() (*ProjectConfig, error) {
	var cfg ProjectConfig
	_, err := toml.DecodeFile(".vault.toml", &cfg)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return &cfg, nil
}
