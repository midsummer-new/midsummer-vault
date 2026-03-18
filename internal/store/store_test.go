package store

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// testStoreAt creates a store at a specific directory (for global vault tests).
func testStoreAt(t *testing.T, dir string) *Store {
	t.Helper()
	vaultPath := filepath.Join(dir, ".vault")
	os.MkdirAll(vaultPath, 0700)

	key := make([]byte, 32)
	rand.Read(key)

	os.WriteFile(filepath.Join(vaultPath, "key"), []byte(hex.EncodeToString(key)), 0600)

	return &Store{dir: vaultPath, key: key, env: DefaultEnv}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, ".vault")
	os.MkdirAll(vaultPath, 0700)

	key := make([]byte, 32)
	rand.Read(key)

	// write key file
	os.WriteFile(filepath.Join(vaultPath, "key"), []byte(hex.EncodeToString(key)), 0600)

	return &Store{dir: vaultPath, key: key, env: DefaultEnv}
}

func testStoreWithEnv(t *testing.T, env string) *Store {
	t.Helper()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, ".vault")
	os.MkdirAll(vaultPath, 0700)

	key := make([]byte, 32)
	rand.Read(key)

	os.WriteFile(filepath.Join(vaultPath, "key"), []byte(hex.EncodeToString(key)), 0600)

	return &Store{dir: vaultPath, key: key, env: env}
}

func TestSetGetRoundTrip(t *testing.T) {
	s := testStore(t)

	if err := s.Set("API_KEY", "sk_live_123"); err != nil {
		t.Fatal(err)
	}

	val, err := s.Get("API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if val != "sk_live_123" {
		t.Fatalf("got %q, want sk_live_123", val)
	}
}

func TestSetMultiple(t *testing.T) {
	s := testStore(t)

	s.Set("A", "1")
	s.Set("B", "2")
	s.Set("C", "3")

	all, err := s.GetAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("got %d secrets, want 3", len(all))
	}
	if all["B"] != "2" {
		t.Fatalf("B=%q, want 2", all["B"])
	}
}

func TestOverwrite(t *testing.T) {
	s := testStore(t)

	s.Set("KEY", "old")
	s.Set("KEY", "new")

	val, err := s.Get("KEY")
	if err != nil {
		t.Fatal(err)
	}
	if val != "new" {
		t.Fatalf("got %q, want new", val)
	}
}

func TestDelete(t *testing.T) {
	s := testStore(t)

	s.Set("A", "1")
	s.Set("B", "2")

	if err := s.Delete("A"); err != nil {
		t.Fatal(err)
	}

	_, err := s.Get("A")
	if err == nil {
		t.Fatal("expected error for deleted key")
	}

	val, _ := s.Get("B")
	if val != "2" {
		t.Fatalf("B should still exist, got %q", val)
	}
}

func TestDeleteNonExistent(t *testing.T) {
	s := testStore(t)
	err := s.Delete("NOPE")
	if err == nil {
		t.Fatal("expected error for non-existent key")
	}
}

func TestList(t *testing.T) {
	s := testStore(t)

	s.Set("ZEBRA", "z")
	s.Set("ALPHA", "a")
	s.Set("MIDDLE", "m")

	names, err := s.List()
	if err != nil {
		t.Fatal(err)
	}

	sort.Strings(names)
	if len(names) != 3 || names[0] != "ALPHA" || names[1] != "MIDDLE" || names[2] != "ZEBRA" {
		t.Fatalf("got %v", names)
	}
}

func TestEmptyStore(t *testing.T) {
	s := testStore(t)

	names, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("expected empty, got %v", names)
	}

	all, err := s.GetAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Fatalf("expected empty, got %v", all)
	}
}

func TestWrongKey(t *testing.T) {
	s := testStore(t)
	s.Set("SECRET", "value")

	// swap to a different key
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)
	s.key = wrongKey

	_, err := s.Get("SECRET")
	if err == nil {
		t.Fatal("expected decrypt error with wrong key")
	}
}

func TestLargeValues(t *testing.T) {
	s := testStore(t)

	// 100KB value
	bigValue := make([]byte, 100000)
	for i := range bigValue {
		bigValue[i] = byte('A' + (i % 26))
	}

	if err := s.Set("BIG", string(bigValue)); err != nil {
		t.Fatal(err)
	}

	val, err := s.Get("BIG")
	if err != nil {
		t.Fatal(err)
	}
	if val != string(bigValue) {
		t.Fatal("large value roundtrip failed")
	}
}

func TestRenameBasic(t *testing.T) {
	s := testStore(t)
	s.Set("OLD_NAME", "secret_value")

	if err := s.Rename("OLD_NAME", "NEW_NAME"); err != nil {
		t.Fatal(err)
	}

	// new name should return the value
	val, err := s.Get("NEW_NAME")
	if err != nil {
		t.Fatal(err)
	}
	if val != "secret_value" {
		t.Fatalf("got %q, want secret_value", val)
	}

	// old name should be gone
	_, err = s.Get("OLD_NAME")
	if err == nil {
		t.Fatal("expected error for old name after rename")
	}
}

func TestRenameNonExistent(t *testing.T) {
	s := testStore(t)
	err := s.Rename("DOES_NOT_EXIST", "NEW_NAME")
	if err == nil {
		t.Fatal("expected error renaming non-existent key")
	}
}

func TestRenameToExistingName(t *testing.T) {
	s := testStore(t)
	s.Set("SOURCE", "source_val")
	s.Set("TARGET", "target_val")

	err := s.Rename("SOURCE", "TARGET")
	if err == nil {
		t.Fatal("expected error renaming to existing name")
	}

	// both originals should be untouched
	val, _ := s.Get("SOURCE")
	if val != "source_val" {
		t.Fatalf("SOURCE should be unchanged, got %q", val)
	}
	val, _ = s.Get("TARGET")
	if val != "target_val" {
		t.Fatalf("TARGET should be unchanged, got %q", val)
	}
}

func TestRenameOldNameGone(t *testing.T) {
	s := testStore(t)
	s.Set("ALPHA", "a")
	s.Set("BETA", "b")
	s.Set("GAMMA", "g")

	if err := s.Rename("BETA", "DELTA"); err != nil {
		t.Fatal(err)
	}

	names, err := s.List()
	if err != nil {
		t.Fatal(err)
	}

	// should have ALPHA, GAMMA, DELTA — no BETA
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}

	if nameSet["BETA"] {
		t.Fatal("BETA should not exist after rename")
	}
	if !nameSet["DELTA"] {
		t.Fatal("DELTA should exist after rename")
	}
	if !nameSet["ALPHA"] || !nameSet["GAMMA"] {
		t.Fatal("other keys should be untouched")
	}
	if len(names) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(names))
	}
}

func TestSpecialCharacters(t *testing.T) {
	s := testStore(t)

	cases := map[string]string{
		"URL":     "postgres://user:p@ss=w0rd@host:5432/db?ssl=true",
		"JSON":    `{"key": "value", "nested": {"a": 1}}`,
		"UNICODE": "emoji: \U0001F512 umlaut: \u00FC accent: \u00E9",
		"NEWLINE": "line1\nline2\nline3",
		"EMPTY":   "",
	}

	for k, v := range cases {
		if err := s.Set(k, v); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}

	for k, want := range cases {
		got, err := s.Get(k)
		if err != nil {
			t.Fatalf("get %s: %v", k, err)
		}
		if got != want {
			t.Fatalf("%s: got %q, want %q", k, got, want)
		}
	}
}

func TestFindVaultDirStopsAtGitRoot(t *testing.T) {
	// create a temp dir structure: /tmp/root/.git/ + /tmp/root/sub/
	// vault in /tmp/root/.vault/ should be found from /tmp/root/sub/
	// but a vault above the git root should NOT be found

	root := t.TempDir()
	// resolve symlinks (macOS /var -> /private/var) so paths match
	root, _ = filepath.EvalSymlinks(root)

	// create git root marker
	os.MkdirAll(filepath.Join(root, ".git"), 0755)

	// create a vault at root level
	vaultPath := filepath.Join(root, ".vault")
	os.MkdirAll(vaultPath, 0700)
	key := make([]byte, 32)
	rand.Read(key)
	os.WriteFile(filepath.Join(vaultPath, "key"), []byte(hex.EncodeToString(key)), 0600)

	// create a subdirectory
	subDir := filepath.Join(root, "sub", "deep")
	os.MkdirAll(subDir, 0755)

	// change to subdirectory — findVaultDir should find .vault/ at root
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(subDir)

	dir, err := findVaultDir()
	if err != nil {
		t.Fatalf("expected to find vault dir, got error: %v", err)
	}
	if dir != vaultPath {
		t.Fatalf("expected %q, got %q", vaultPath, dir)
	}
}

func TestFindVaultDirDoesNotCrossGitBoundary(t *testing.T) {
	// create: /tmp/parent/.vault/ + /tmp/parent/project/.git/
	// from /tmp/parent/project/, findVaultDir should NOT find /tmp/parent/.vault/

	parent := t.TempDir()

	// create vault above the git root
	parentVault := filepath.Join(parent, ".vault")
	os.MkdirAll(parentVault, 0700)
	key := make([]byte, 32)
	rand.Read(key)
	os.WriteFile(filepath.Join(parentVault, "key"), []byte(hex.EncodeToString(key)), 0600)

	// create a project with .git inside parent
	project := filepath.Join(parent, "project")
	os.MkdirAll(filepath.Join(project, ".git"), 0755)

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(project)

	_, err := findVaultDir()
	if err == nil {
		t.Fatal("expected error — vault should not be found across git boundary")
	}
}

func TestGlobalVaultInitAndOpen(t *testing.T) {
	// override HOME to a temp dir so InitGlobal and OpenGlobal use it
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpHome)

	// should not exist yet
	if GlobalExists() {
		t.Fatal("global vault should not exist before init")
	}

	// init
	hexKey, err := InitGlobal()
	if err != nil {
		t.Fatalf("InitGlobal: %v", err)
	}
	if len(hexKey) != 64 {
		t.Fatalf("expected 64-char hex key, got %d chars", len(hexKey))
	}

	// should exist now
	if !GlobalExists() {
		t.Fatal("global vault should exist after init")
	}

	// open and set a secret
	gs, err := OpenGlobal()
	if err != nil {
		t.Fatalf("OpenGlobal: %v", err)
	}
	if err := gs.Set("GLOBAL_KEY", "global_value"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	val, err := gs.Get("GLOBAL_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "global_value" {
		t.Fatalf("expected global_value, got %q", val)
	}
}

func TestGlobalVaultInitTwiceFails(t *testing.T) {
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", tmpHome)

	_, err := InitGlobal()
	if err != nil {
		t.Fatalf("first InitGlobal: %v", err)
	}

	_, err = InitGlobal()
	if err == nil {
		t.Fatal("expected error on second InitGlobal")
	}
}

func TestMergeLocalWins(t *testing.T) {
	localStore := testStore(t)
	globalDir := t.TempDir()
	globalStore := testStoreAt(t, globalDir)

	// global has A=global_a, B=global_b
	globalStore.Set("A", "global_a")
	globalStore.Set("B", "global_b")

	// local has B=local_b, C=local_c
	localStore.Set("B", "local_b")
	localStore.Set("C", "local_c")

	// merge: local wins on conflict
	merged, err := localStore.Merge(globalStore)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	if len(merged) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(merged))
	}
	if merged["A"] != "global_a" {
		t.Fatalf("A: expected global_a, got %q", merged["A"])
	}
	if merged["B"] != "local_b" {
		t.Fatalf("B: expected local_b (local wins), got %q", merged["B"])
	}
	if merged["C"] != "local_c" {
		t.Fatalf("C: expected local_c, got %q", merged["C"])
	}
}

func TestMergeEmptyStores(t *testing.T) {
	s1 := testStore(t)
	s2Dir := t.TempDir()
	s2 := testStoreAt(t, s2Dir)

	merged, err := s1.Merge(s2)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(merged) != 0 {
		t.Fatalf("expected empty merge, got %d keys", len(merged))
	}
}

func TestMergeOnlyGlobalSecrets(t *testing.T) {
	localStore := testStore(t)
	globalDir := t.TempDir()
	globalStore := testStoreAt(t, globalDir)

	// only global has secrets
	globalStore.Set("OPENAI_KEY", "sk-123")

	merged, err := localStore.Merge(globalStore)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(merged) != 1 || merged["OPENAI_KEY"] != "sk-123" {
		t.Fatalf("expected OPENAI_KEY=sk-123, got %v", merged)
	}
}

func TestDir(t *testing.T) {
	s := testStore(t)
	if s.Dir() == "" {
		t.Fatal("Dir() should return non-empty path")
	}
}

func TestIsGitRoot(t *testing.T) {
	dir := t.TempDir()

	// no .git — not a git root
	if isGitRoot(dir) {
		t.Fatal("should not be git root without .git")
	}

	// create .git directory
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	if !isGitRoot(dir) {
		t.Fatal("should be git root with .git directory")
	}
}

func TestIsGitRootSubmodule(t *testing.T) {
	dir := t.TempDir()

	// .git as a file (submodule style)
	os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: ../../../.git/modules/sub"), 0644)
	if !isGitRoot(dir) {
		t.Fatal("should be git root with .git file (submodule)")
	}
}

// --- environment tests ---

func TestEnvironmentIsolation(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, ".vault")
	os.MkdirAll(vaultPath, 0700)

	key := make([]byte, 32)
	rand.Read(key)
	os.WriteFile(filepath.Join(vaultPath, "key"), []byte(hex.EncodeToString(key)), 0600)

	dev := &Store{dir: vaultPath, key: key, env: "development"}
	prod := &Store{dir: vaultPath, key: key, env: "production"}

	dev.Set("DB_URL", "postgres://localhost/dev")
	prod.Set("DB_URL", "postgres://rds/prod")

	devVal, _ := dev.Get("DB_URL")
	prodVal, _ := prod.Get("DB_URL")

	if devVal != "postgres://localhost/dev" {
		t.Fatalf("dev DB_URL = %q, want postgres://localhost/dev", devVal)
	}
	if prodVal != "postgres://rds/prod" {
		t.Fatalf("prod DB_URL = %q, want postgres://rds/prod", prodVal)
	}
}

func TestSecretsPathContainsEnv(t *testing.T) {
	s := testStoreWithEnv(t, "staging")
	path := s.SecretsPath()
	if !filepath.IsAbs(path) || filepath.Base(path) != "secrets.staging.enc" {
		t.Fatalf("unexpected secrets path: %s", path)
	}
}

func TestLegacyMigration(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, ".vault")
	os.MkdirAll(vaultPath, 0700)

	key := make([]byte, 32)
	rand.Read(key)
	os.WriteFile(filepath.Join(vaultPath, "key"), []byte(hex.EncodeToString(key)), 0600)

	// write secrets using legacy file name
	legacy := &Store{dir: vaultPath, key: key, env: "development"}
	// manually write to legacy path
	legacyPath := filepath.Join(vaultPath, "secrets.enc")
	devPath := filepath.Join(vaultPath, "secrets.development.enc")

	// create a store, set a secret, then rename the file to legacy name
	legacy.Set("LEGACY_KEY", "legacy_value")
	os.Rename(devPath, legacyPath)

	// verify legacy file exists, dev file doesn't
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatal("legacy file should exist")
	}
	if _, err := os.Stat(devPath); err == nil {
		t.Fatal("dev file should not exist yet")
	}

	// creating a new store should trigger migration
	migrated := &Store{dir: vaultPath, key: key, env: "development"}
	migrated.migrateLegacyFile()

	// legacy should be gone, dev file should exist
	if _, err := os.Stat(legacyPath); err == nil {
		t.Fatal("legacy file should have been renamed")
	}
	if _, err := os.Stat(devPath); err != nil {
		t.Fatal("dev file should exist after migration")
	}

	val, err := migrated.Get("LEGACY_KEY")
	if err != nil {
		t.Fatalf("Get after migration: %v", err)
	}
	if val != "legacy_value" {
		t.Fatalf("got %q, want legacy_value", val)
	}
}

func TestInvalidEnvironment(t *testing.T) {
	if isValidEnv("invalid") {
		t.Fatal("should reject invalid environment")
	}
	if !isValidEnv("production") {
		t.Fatal("should accept production")
	}
}

func TestEnvAccessor(t *testing.T) {
	s := testStoreWithEnv(t, "staging")
	if s.Env() != "staging" {
		t.Fatalf("Env() = %q, want staging", s.Env())
	}
}
