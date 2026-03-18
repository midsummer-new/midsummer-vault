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

	"golang.org/x/crypto/argon2"
)

const (
	vaultDir    = ".vault"
	keyFile     = "key"
	ivLength    = 12
	legacyFile  = "secrets.enc"             // pre-environment flat file
	DefaultEnv  = "development"
)

// ValidEnvironments lists accepted environment names.
var ValidEnvironments = []string{"development", "staging", "production"}

// Store manages locally encrypted secrets in .vault/secrets.{env}.enc.
type Store struct {
	dir string // .vault directory path
	key []byte // 32-byte AES-256 key
	env string // environment name (development, staging, production)
}

// Open finds or creates a local vault store for the default environment (development).
// Key resolution order: VAULT_KEY env > .vault/key file.
func Open() (*Store, error) {
	return OpenWithEnv(DefaultEnv)
}

// OpenWithEnv finds or creates a local vault store for a specific environment.
// On first access, migrates the legacy secrets.enc to secrets.development.enc.
func OpenWithEnv(env string) (*Store, error) {
	if !isValidEnv(env) {
		return nil, fmt.Errorf("invalid environment %q — must be one of: development, staging, production", env)
	}
	dir, err := findVaultDir()
	if err != nil {
		return nil, err
	}
	key, err := resolveKey(dir)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, key: key, env: env}
	s.migrateLegacyFile()
	return s, nil
}

// OpenGlobal opens the global vault at ~/.vault/ for the default environment.
func OpenGlobal() (*Store, error) {
	return OpenGlobalWithEnv(DefaultEnv)
}

// OpenGlobalWithEnv opens the global vault at ~/.vault/ for a specific environment.
func OpenGlobalWithEnv(env string) (*Store, error) {
	if !isValidEnv(env) {
		return nil, fmt.Errorf("invalid environment %q — must be one of: development, staging, production", env)
	}
	dir, err := globalVaultDir()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, fmt.Errorf("no global vault found — run `vault init --global` to create one")
	}
	key, err := resolveKey(dir)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, key: key, env: env}
	s.migrateLegacyFile()
	return s, nil
}

// GlobalExists checks if a global vault exists at ~/.vault/.
func GlobalExists() bool {
	dir, err := globalVaultDir()
	if err != nil {
		return false
	}
	keyPath := filepath.Join(dir, keyFile)
	if _, err := os.Stat(keyPath); err == nil {
		return true
	}
	return os.Getenv("VAULT_KEY") != ""
}

// Dir returns the vault directory path.
func (s *Store) Dir() string {
	return s.dir
}

// Init creates a new local vault in the current directory.
// Returns the generated key (hex) for display.
func Init() (string, error) {
	dir := filepath.Join(".", vaultDir)
	return initVaultAt(dir)
}

// InitGlobal creates a new global vault at ~/.vault/.
// Returns the generated key (hex) for display.
func InitGlobal() (string, error) {
	dir, err := globalVaultDir()
	if err != nil {
		return "", err
	}
	return initVaultAt(dir)
}

// initVaultAt creates a vault at the given directory path.
func initVaultAt(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}

	keyPath := filepath.Join(dir, keyFile)
	if _, err := os.Stat(keyPath); err == nil {
		return "", fmt.Errorf("%s/key already exists — vault is already initialized", dir)
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

	// create empty secrets file for the default environment
	s := &Store{dir: dir, key: rawKey, env: DefaultEnv}
	if err := s.writeSecrets(map[string]string{}); err != nil {
		return "", fmt.Errorf("init secrets: %w", err)
	}

	// write .gitignore — allow docs/ to be committed (no secret values there)
	gitignore := "# never commit secrets or the key\n*\n!.gitignore\n!docs/\n!docs/**\n"
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

// Merge combines secrets from another store into this store's secrets.
// Returns a new map where this store's values win on key conflicts.
func (s *Store) Merge(other *Store) (map[string]string, error) {
	base, err := other.GetAll()
	if err != nil {
		return nil, fmt.Errorf("read other store: %w", err)
	}
	local, err := s.GetAll()
	if err != nil {
		return nil, fmt.Errorf("read local store: %w", err)
	}
	// local wins on conflict
	for k, v := range local {
		base[k] = v
	}
	return base, nil
}

// --- internal ---

// Env returns the environment name this store targets.
func (s *Store) Env() string {
	return s.env
}

// SecretsPath returns the path to the encrypted secrets file for this environment.
func (s *Store) SecretsPath() string {
	return s.secretsPath()
}

func (s *Store) secretsPath() string {
	return filepath.Join(s.dir, fmt.Sprintf("secrets.%s.enc", s.env))
}

// migrateLegacyFile renames .vault/secrets.enc → .vault/secrets.development.enc
// if the legacy file exists and the new per-env file doesn't.
func (s *Store) migrateLegacyFile() {
	if s.env != DefaultEnv {
		return
	}
	legacy := filepath.Join(s.dir, legacyFile)
	target := s.secretsPath()

	// only migrate if legacy exists and target doesn't
	if _, err := os.Stat(legacy); err != nil {
		return
	}
	if _, err := os.Stat(target); err == nil {
		return // target already exists, don't clobber
	}

	os.Rename(legacy, target)
}

func isValidEnv(env string) bool {
	for _, v := range ValidEnvironments {
		if v == env {
			return true
		}
	}
	return false
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
// Stops at the git root (directory containing .git/) to avoid crossing project boundaries.
func findVaultDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		candidate := filepath.Join(dir, vaultDir)
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			// verify it has a key file, salt file (passphrase), or VAULT_KEY/VAULT_PASSPHRASE env
			if _, err := os.Stat(filepath.Join(candidate, keyFile)); err == nil {
				return candidate, nil
			}
			if _, err := os.Stat(filepath.Join(candidate, saltFile)); err == nil {
				return candidate, nil
			}
			if os.Getenv("VAULT_KEY") != "" || os.Getenv("VAULT_PASSPHRASE") != "" {
				return candidate, nil
			}
		}

		// stop at git root — never cross project boundaries
		if isGitRoot(dir) {
			break
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("no .vault/ found — run `vault init` to create one")
}

// isGitRoot returns true if dir contains a .git/ directory or .git file (submodule).
func isGitRoot(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

// globalVaultDir returns ~/.vault/ path.
func globalVaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, vaultDir), nil
}

// resolveKey gets the encryption key from VAULT_KEY env or .vault/key file.
func resolveKey(vaultDir string) ([]byte, error) {
	// 1. VAULT_KEY env var (for CI/CD with key file vaults)
	if envKey := os.Getenv("VAULT_KEY"); envKey != "" {
		return decodeHexKey(envKey)
	}

	// 2. VAULT_PASSPHRASE env var (for CI/CD with passphrase vaults)
	if passphrase := os.Getenv("VAULT_PASSPHRASE"); passphrase != "" {
		saltPath := filepath.Join(vaultDir, saltFile)
		saltHex, err := os.ReadFile(saltPath)
		if err != nil {
			return nil, fmt.Errorf("VAULT_PASSPHRASE set but no salt file found — is this a passphrase vault?")
		}
		salt, err := hex.DecodeString(strings.TrimSpace(string(saltHex)))
		if err != nil {
			return nil, fmt.Errorf("decode salt: %w", err)
		}
		return argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen), nil
	}

	// 3. .vault/key file
	keyPath := filepath.Join(vaultDir, keyFile)
	data, err := os.ReadFile(keyPath)
	if err == nil {
		return decodeHexKey(strings.TrimSpace(string(data)))
	}

	// 4. passphrase vault (has salt but no key) — need VAULT_PASSPHRASE env
	saltPath := filepath.Join(vaultDir, saltFile)
	if _, saltErr := os.Stat(saltPath); saltErr == nil {
		return nil, fmt.Errorf("this is a passphrase-protected vault — set VAULT_PASSPHRASE env var or run with: VAULT_PASSPHRASE=yourpass vault <command>")
	}

	return nil, fmt.Errorf("no key found — set VAULT_KEY env or run `vault init`")
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
