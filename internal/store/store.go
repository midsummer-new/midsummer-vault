package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	vaultDir     = ".vault"
	secretsFile  = "secrets.enc"
	keyFile      = "key"
	ivLength     = 12
)

// Store manages locally encrypted secrets in .vault/secrets.enc.
type Store struct {
	dir string // .vault directory path
	key []byte // 32-byte AES-256 key
}

// Open finds or creates a local vault store.
// Key resolution order: VAULT_KEY env > .vault/key file.
func Open() (*Store, error) {
	dir, err := findVaultDir()
	if err != nil {
		return nil, err
	}
	key, err := resolveKey(dir)
	if err != nil {
		return nil, err
	}
	return &Store{dir: dir, key: key}, nil
}

// Init creates a new local vault in the current directory.
// Returns the generated key (hex) for display.
func Init() (string, error) {
	dir := filepath.Join(".", vaultDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create .vault: %w", err)
	}

	keyPath := filepath.Join(dir, keyFile)
	if _, err := os.Stat(keyPath); err == nil {
		return "", fmt.Errorf(".vault/key already exists — vault is already initialized")
	}

	// generate 32-byte random key
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}

	hexKey := hex.EncodeToString(rawKey)
	if err := os.WriteFile(keyPath, []byte(hexKey+"\n"), 0600); err != nil {
		return "", fmt.Errorf("write key: %w", err)
	}

	// create empty secrets file
	s := &Store{dir: dir, key: rawKey}
	if err := s.writeSecrets(map[string]string{}); err != nil {
		return "", fmt.Errorf("init secrets: %w", err)
	}

	// write .gitignore inside .vault/
	gitignore := "# never commit secrets or the key\n*\n!.gitignore\n"
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(gitignore), 0644)

	return hexKey, nil
}

// Exists checks if a local vault exists in the current or parent directories.
func Exists() bool {
	_, err := findVaultDir()
	return err == nil
}

// Set encrypts and stores a secret.
func (s *Store) Set(name, value string) error {
	secrets, err := s.readSecrets()
	if err != nil {
		return err
	}
	secrets[name] = value
	return s.writeSecrets(secrets)
}

// Get decrypts and returns a single secret.
func (s *Store) Get(name string) (string, error) {
	secrets, err := s.readSecrets()
	if err != nil {
		return "", err
	}
	v, ok := secrets[name]
	if !ok {
		return "", fmt.Errorf("secret %q not found", name)
	}
	return v, nil
}

// Rename moves a secret from oldName to newName.
// This maps auto-detected secrets to proper env var names.
func (s *Store) Rename(oldName, newName string) error {
	secrets, err := s.readSecrets()
	if err != nil {
		return err
	}
	val, ok := secrets[oldName]
	if !ok {
		return fmt.Errorf("secret %q not found", oldName)
	}
	if _, exists := secrets[newName]; exists {
		return fmt.Errorf("secret %q already exists — delete it first or choose another name", newName)
	}
	secrets[newName] = val
	delete(secrets, oldName)
	return s.writeSecrets(secrets)
}

// Delete removes a secret.
func (s *Store) Delete(name string) error {
	secrets, err := s.readSecrets()
	if err != nil {
		return err
	}
	if _, ok := secrets[name]; !ok {
		return fmt.Errorf("secret %q not found", name)
	}
	delete(secrets, name)
	return s.writeSecrets(secrets)
}

// List returns all secret names (not values).
func (s *Store) List() ([]string, error) {
	secrets, err := s.readSecrets()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(secrets))
	for k := range secrets {
		names = append(names, k)
	}
	return names, nil
}

// GetAll returns all secrets (name → value). Used by `vault run`.
func (s *Store) GetAll() (map[string]string, error) {
	return s.readSecrets()
}

// --- internal ---

func (s *Store) secretsPath() string {
	return filepath.Join(s.dir, secretsFile)
}

func (s *Store) readSecrets() (map[string]string, error) {
	data, err := os.ReadFile(s.secretsPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("read secrets: %w", err)
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return map[string]string{}, nil
	}

	// format: base64(iv):base64(ciphertext+authTag)
	parts := strings.SplitN(content, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("corrupt secrets file — invalid format")
	}

	iv, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode IV: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, ivLength)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt secrets (wrong key?): %w", err)
	}

	var secrets map[string]string
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, fmt.Errorf("parse secrets: %w", err)
	}
	return secrets, nil
}

func (s *Store) writeSecrets(secrets map[string]string) error {
	plaintext, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("marshal secrets: %w", err)
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, ivLength)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	iv := make([]byte, ivLength)
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("generate IV: %w", err)
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	encoded := base64.StdEncoding.EncodeToString(iv) + ":" + base64.StdEncoding.EncodeToString(ciphertext)
	return os.WriteFile(s.secretsPath(), []byte(encoded), 0600)
}

// findVaultDir walks up from cwd looking for a .vault/ directory.
func findVaultDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		candidate := filepath.Join(dir, vaultDir)
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			// verify it has a key file or VAULT_KEY is set
			if _, err := os.Stat(filepath.Join(candidate, keyFile)); err == nil {
				return candidate, nil
			}
			if os.Getenv("VAULT_KEY") != "" {
				return candidate, nil
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("no .vault/ found — run `vault init` to create one")
}

// resolveKey gets the encryption key from VAULT_KEY env or .vault/key file.
func resolveKey(vaultDir string) ([]byte, error) {
	// 1. VAULT_KEY env var (for CI/CD)
	if envKey := os.Getenv("VAULT_KEY"); envKey != "" {
		return decodeHexKey(envKey)
	}

	// 2. .vault/key file
	keyPath := filepath.Join(vaultDir, keyFile)
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("no key found — set VAULT_KEY env or run `vault init`")
	}

	return decodeHexKey(strings.TrimSpace(string(data)))
}

func decodeHexKey(hexStr string) ([]byte, error) {
	key, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid key (must be 64-char hex): %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}
	return key, nil
}
