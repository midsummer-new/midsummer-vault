package store

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, ".vault")
	os.MkdirAll(vaultPath, 0700)

	key := make([]byte, 32)
	rand.Read(key)

	// write key file
	os.WriteFile(filepath.Join(vaultPath, "key"), []byte(hex.EncodeToString(key)), 0600)

	return &Store{dir: vaultPath, key: key}
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
