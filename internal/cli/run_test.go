package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadDotEnv(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env.local")

	content := `# Comment
STRIPE_SECRET_KEY=sk_test_123
DATABASE_URL="postgres://localhost:5432/db"
EMPTY=
QUOTED_SINGLE='single-quoted'

API_KEY=key_with_equals=in=value
`
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result := readDotEnv(envFile)

	tests := map[string]string{
		"STRIPE_SECRET_KEY": "sk_test_123",
		"DATABASE_URL":      "postgres://localhost:5432/db",
		"EMPTY":             "",
		"QUOTED_SINGLE":     "single-quoted",
		"API_KEY":           "key_with_equals=in=value",
	}

	for k, want := range tests {
		got, ok := result[k]
		if !ok {
			t.Errorf("missing key %s", k)
			continue
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", k, got, want)
		}
	}
}

func TestReadDotEnv_MissingFile(t *testing.T) {
	result := readDotEnv("/nonexistent/.env.local")
	if len(result) != 0 {
		t.Errorf("expected empty map, got %v", result)
	}
}
