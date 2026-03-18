package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

const (
	saltFile    = "salt"
	argonTime   = 3
	argonMemory = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen = 32
)

// InitWithPassphrase creates a vault using a passphrase-derived key.
// The salt is stored in .vault/salt (needed for re-derivation).
// No .vault/key file is created — the key exists only in memory.
func InitWithPassphrase(passphrase string) error {
	dir := filepath.Join(".", vaultDir)
	return initWithPassphraseAt(dir, passphrase)
}

// InitGlobalWithPassphrase creates a global vault with passphrase.
func InitGlobalWithPassphrase(passphrase string) error {
	dir, err := globalVaultDir()
	if err != nil {
		return err
	}
	return initWithPassphraseAt(dir, passphrase)
}

func initWithPassphraseAt(dir, passphrase string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	keyPath := filepath.Join(dir, keyFile)
	saltPath := filepath.Join(dir, saltFile)

	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("%s/key already exists — vault is already initialized", dir)
	}
	if _, err := os.Stat(saltPath); err == nil {
		return fmt.Errorf("%s/salt already exists — vault is already initialized", dir)
	}

	// generate random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	// derive key from passphrase using Argon2id
	key := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	// store salt (NOT the key — key is derived from passphrase each time)
	if err := os.WriteFile(saltPath, []byte(hex.EncodeToString(salt)+"\n"), 0600); err != nil {
		return fmt.Errorf("write salt: %w", err)
	}

	// create empty secrets file
	s := &Store{dir: dir, key: key, env: DefaultEnv}
	if err := s.writeSecrets(map[string]string{}); err != nil {
		return fmt.Errorf("init secrets: %w", err)
	}

	// write .gitignore
	gitignore := "# never commit secrets or the key\n*\n!.gitignore\n!docs/\n!docs/**\n"
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(gitignore), 0644)

	return nil
}

// OpenWithPassphrase opens a vault using a passphrase.
// Reads the salt from .vault/salt, derives key with Argon2id.
func OpenWithPassphrase(passphrase string) (*Store, error) {
	dir, err := findVaultDir()
	if err != nil {
		return nil, err
	}
	return openWithPassphraseAt(dir, passphrase, DefaultEnv)
}

// IsPassphraseVault checks if the vault uses a passphrase (has salt, no key file).
func IsPassphraseVault() bool {
	dir, err := findVaultDir()
	if err != nil {
		return false
	}
	saltPath := filepath.Join(dir, saltFile)
	keyPath := filepath.Join(dir, keyFile)

	saltExists := false
	if _, err := os.Stat(saltPath); err == nil {
		saltExists = true
	}
	keyExists := false
	if _, err := os.Stat(keyPath); err == nil {
		keyExists = true
	}
	return saltExists && !keyExists
}

func openWithPassphraseAt(dir, passphrase, env string) (*Store, error) {
	saltPath := filepath.Join(dir, saltFile)
	saltHex, err := os.ReadFile(saltPath)
	if err != nil {
		return nil, fmt.Errorf("read salt: %w — is this a passphrase vault?", err)
	}

	salt, err := hex.DecodeString(trimSpace(string(saltHex)))
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}

	key := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return &Store{dir: dir, key: key, env: env}, nil
}

func trimSpace(s string) string {
	// trim whitespace and newlines
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
