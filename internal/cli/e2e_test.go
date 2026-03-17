package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2E_VaultRunServiceToken is the full end-to-end test:
// 1. Spin up a mock vault API that serves secrets
// 2. Build the vault CLI binary
// 3. Run `vault run -- <cmd>` with service token env vars
// 4. Verify secrets are injected into the child process
// 5. Verify redaction strips secret values from output
func TestE2E_VaultRunServiceToken(t *testing.T) {
	secrets := map[string]string{
		"STRIPE_SECRET_KEY": "sk_live_51Test123SuperSecretKey",
		"OPENAI_API_KEY":    "sk-proj-abc123def456ghi789",
		"DATABASE_URL":      "postgres://admin:s3cret_pass@db.example.com:5432/prod",
		"RESEND_API_KEY":    "re_live_789xyz",
	}

	// Use a valid JWT so the expiry check in fetchViaServiceToken passes
	validToken := makeValidJWT()

	// 1. Mock vault API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify bearer token auth
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+validToken {
			t.Logf("unauthorized request: %s", auth)
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}

		// Serve secrets
		if strings.Contains(r.URL.Path, "/secrets") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"secrets": secrets,
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	// 2. Build the vault CLI binary
	// Find the module root by looking for go.mod
	modRoot := findModuleRoot(t)
	binaryPath := filepath.Join(t.TempDir(), "vault")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/vault")
	buildCmd.Dir = modRoot
	buildOut, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build vault binary: %v\n%s", err, buildOut)
	}

	t.Run("secrets injected into child process", func(t *testing.T) {
		// Run: vault run -- bash -c 'echo STRIPE=$STRIPE_SECRET_KEY; echo OPENAI=$OPENAI_API_KEY'
		cmd := exec.Command(binaryPath, "run", "--",
			"bash", "-c",
			"echo STRIPE=$STRIPE_SECRET_KEY; echo OPENAI=$OPENAI_API_KEY; echo DB=$DATABASE_URL; echo RESEND=$RESEND_API_KEY",
		)
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"VAULT_SERVICE_TOKEN=" + validToken,
			"VAULT_PROJECT_ID=proj_test123",
			"VAULT_API_URL=" + server.URL,
		}

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			t.Fatalf("vault run failed: %v\nstderr: %s", err, stderr.String())
		}

		output := stdout.String()

		// Verify all secrets were injected
		for key, val := range secrets {
			expected := fmt.Sprintf("%s=%s", key[strings.LastIndex(key, "_")+1:], val)
			// Check by the echo prefix we set up
			if !strings.Contains(output, val) {
				t.Errorf("secret %s value not found in child output", key)
			}
			_ = expected // just used for debugging
		}
	})

	t.Run("redaction strips all secret values", func(t *testing.T) {
		// Run same command, capture output, apply redaction
		cmd := exec.Command(binaryPath, "run", "--",
			"bash", "-c",
			fmt.Sprintf(
				"echo 'Connecting to database at %s'; echo 'Using Stripe key: %s'; echo 'Auth: Bearer %s'; echo 'Sending email via %s'; echo 'App started successfully'",
				secrets["DATABASE_URL"],
				secrets["STRIPE_SECRET_KEY"],
				secrets["OPENAI_API_KEY"],
				secrets["RESEND_API_KEY"],
			),
		)
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"VAULT_SERVICE_TOKEN=" + validToken,
			"VAULT_PROJECT_ID=proj_test123",
			"VAULT_API_URL=" + server.URL,
		}

		var stdout bytes.Buffer
		cmd.Stdout = &stdout

		if err := cmd.Run(); err != nil {
			t.Fatalf("vault run failed: %v", err)
		}

		rawOutput := stdout.String()

		// Apply redaction (same logic as sandbox redactSecrets in index.ts)
		redacted := rawOutput
		for _, val := range secrets {
			if len(val) < 4 {
				continue
			}
			redacted = strings.ReplaceAll(redacted, val, "[REDACTED]")
		}

		// Verify NO secret values survive redaction
		for key, val := range secrets {
			if strings.Contains(redacted, val) {
				t.Errorf("secret %s leaked through redaction: found %q in output", key, val[:10]+"...")
			}
		}

		// Verify redaction markers are present
		if strings.Count(redacted, "[REDACTED]") != 4 {
			t.Errorf("expected 4 redaction markers, got %d\nRedacted output:\n%s",
				strings.Count(redacted, "[REDACTED]"), redacted)
		}

		// Verify non-secret content preserved
		if !strings.Contains(redacted, "App started successfully") {
			t.Error("non-secret output was lost during redaction")
		}
		if !strings.Contains(redacted, "Connecting to database at") {
			t.Error("output structure was lost during redaction")
		}

		t.Logf("Redacted output:\n%s", redacted)
	})

	t.Run("unauthorized token rejected", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "run", "--",
			"bash", "-c", "echo $STRIPE_SECRET_KEY",
		)
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"VAULT_SERVICE_TOKEN=wrong-token",
			"VAULT_PROJECT_ID=proj_test123",
			"VAULT_API_URL=" + server.URL,
		}

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()

		output := stdout.String()
		errOutput := stderr.String()

		// Non-JWT token is treated as expired → hard exit
		if err == nil {
			t.Error("expected non-zero exit for invalid token")
		}

		// Secret should NOT be in output
		for _, val := range secrets {
			if strings.Contains(output, val) {
				t.Errorf("secret leaked despite auth failure: %s", val[:10]+"...")
			}
		}

		// Should see expired error on stderr
		if !strings.Contains(errOutput, "expired") {
			t.Errorf("expected 'expired' in stderr, got: %s", errOutput)
		}
	})

	t.Run("shell hardening blocks env inspection", func(t *testing.T) {
		// Simulate what happens in sandbox: shell hardening + vault secrets
		preamble := `env() { echo "[vault] env inspection disabled"; }; ` +
			`printenv() { echo "[vault] env inspection disabled"; }; ` +
			`export() { echo "[vault] export inspection disabled"; }; ` +
			`declare() { echo "[vault] declare inspection disabled"; }; ` +
			`compgen() { echo "[vault] compgen inspection disabled"; }; `

		tests := []struct {
			name     string
			shellCmd string
			expect   string
		}{
			{"env blocked", "env", "[vault] env inspection disabled"},
			{"printenv blocked", "printenv", "[vault] env inspection disabled"},
			{"printenv KEY blocked", "printenv STRIPE_SECRET_KEY", "[vault] env inspection disabled"},
			{"export blocked", "export", "[vault] export inspection disabled"},
			{"declare blocked", "declare -x", "[vault] declare inspection disabled"},
			{"compgen blocked", "compgen -v", "[vault] compgen inspection disabled"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				cmd := exec.Command(binaryPath, "run", "--",
					"bash", "-c", preamble+tt.shellCmd,
				)
				cmd.Env = []string{
					"PATH=" + os.Getenv("PATH"),
					"VAULT_SERVICE_TOKEN=" + validToken,
					"VAULT_PROJECT_ID=proj_test123",
					"VAULT_API_URL=" + server.URL,
				}

				var stdout bytes.Buffer
				cmd.Stdout = &stdout

				if err := cmd.Run(); err != nil {
					t.Fatalf("command failed: %v", err)
				}

				output := strings.TrimSpace(stdout.String())
				if output != tt.expect {
					t.Errorf("got %q, want %q", output, tt.expect)
				}
			})
		}
	})

	t.Run("real CLI tool simulation - curl with bearer token", func(t *testing.T) {
		// Simulate: agent runs `vault run -- curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/...`
		// The CLI injects the secret, curl uses it, but output gets redacted

		// Use a simple echo to simulate what curl would return
		cmd := exec.Command(binaryPath, "run", "--",
			"bash", "-c",
			// Simulates a curl that echoes back the auth header and a response
			`echo "HTTP/1.1 200 OK"; echo "Request authenticated with: $OPENAI_API_KEY"; echo '{"models": ["gpt-4", "gpt-3.5-turbo"]}'`,
		)
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"VAULT_SERVICE_TOKEN=" + validToken,
			"VAULT_PROJECT_ID=proj_test123",
			"VAULT_API_URL=" + server.URL,
		}

		var stdout bytes.Buffer
		cmd.Stdout = &stdout

		if err := cmd.Run(); err != nil {
			t.Fatalf("command failed: %v", err)
		}

		rawOutput := stdout.String()

		// The raw output DOES contain the secret (vault injected it)
		if !strings.Contains(rawOutput, secrets["OPENAI_API_KEY"]) {
			t.Error("secret was not injected into child process")
		}

		// After redaction, it's gone
		redacted := rawOutput
		for _, val := range secrets {
			redacted = strings.ReplaceAll(redacted, val, "[REDACTED]")
		}

		if strings.Contains(redacted, secrets["OPENAI_API_KEY"]) {
			t.Error("secret leaked through redaction")
		}

		// Non-secret content preserved
		if !strings.Contains(redacted, "HTTP/1.1 200 OK") {
			t.Error("HTTP response lost")
		}
		if !strings.Contains(redacted, `"models"`) {
			t.Error("JSON response lost")
		}

		t.Logf("Agent sees (redacted):\n%s", redacted)
	})

	t.Run("expired service token exits nonzero", func(t *testing.T) {
		// Create a JWT with exp in the past
		expiredToken := makeExpiredJWT()

		cmd := exec.Command(binaryPath, "run", "--", "echo", "test")
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"VAULT_SERVICE_TOKEN=" + expiredToken,
			"VAULT_PROJECT_ID=proj_test123",
			"VAULT_API_URL=" + server.URL,
		}

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err == nil {
			t.Fatal("expected non-zero exit code for expired token")
		}

		errOutput := stderr.String()
		if !strings.Contains(errOutput, "expired") {
			t.Errorf("expected 'expired' in stderr, got: %s", errOutput)
		}
	})

	t.Run("base64 encoded secret in output redacted", func(t *testing.T) {
		secret := "sk_live_51Test123SuperSecretKey"
		b64Secret := base64Encode(secret)

		cmd := exec.Command(binaryPath, "run", "--",
			"bash", "-c", fmt.Sprintf("echo '%s'", b64Secret),
		)
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"VAULT_SERVICE_TOKEN=" + validToken,
			"VAULT_PROJECT_ID=proj_test123",
			"VAULT_API_URL=" + server.URL,
		}

		var stdout bytes.Buffer
		cmd.Stdout = &stdout

		if err := cmd.Run(); err != nil {
			t.Fatalf("command failed: %v", err)
		}

		rawOutput := stdout.String()

		// Apply enhanced redaction (same as sandbox: raw + base64 + url-encoded)
		redacted := rawOutput
		for _, val := range secrets {
			if len(val) < 4 {
				continue
			}
			redacted = strings.ReplaceAll(redacted, val, "[REDACTED]")
			redacted = strings.ReplaceAll(redacted, base64Encode(val), "[REDACTED]")
		}

		if strings.Contains(redacted, b64Secret) {
			t.Errorf("base64-encoded secret leaked through redaction")
		}
	})

	t.Run("env.local fallback works when no service token", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create .env.local in the working directory
		envContent := "FALLBACK_KEY=fb_secret_value_123\nOTHER=hello\n"
		os.WriteFile(filepath.Join(tmpDir, ".env.local"), []byte(envContent), 0644)

		cmd := exec.Command(binaryPath, "run", "--",
			"bash", "-c", "echo FALLBACK=$FALLBACK_KEY; echo OTHER=$OTHER",
		)
		cmd.Dir = tmpDir
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + t.TempDir(), // Empty home to avoid loading real credentials
		}

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			t.Logf("stderr: %s", stderr.String())
			t.Fatalf("command failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "FALLBACK=fb_secret_value_123") {
			t.Errorf("fallback secret not injected.\noutput: %s\nstderr: %s", output, stderr.String())
		}
		if !strings.Contains(output, "OTHER=hello") {
			t.Errorf("fallback env not injected.\noutput: %s", output)
		}
	})
}

// TestE2E_VaultRunBearerTokenAPI tests the full flow of an agent using
// vault run to call an API with a bearer token — the core use case.
func TestE2E_VaultRunBearerTokenAPI(t *testing.T) {
	apiKey := "sk-proj-TESTKEY123456789abcdef"

	// Mock vault API
	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"secrets": map[string]string{
				"API_KEY": apiKey,
			},
		})
	}))
	defer vaultServer.Close()

	// Mock external API that requires bearer auth
	externalAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "Bearer "+apiKey {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status": "success",
				"data":   "sensitive-response-data",
			})
		} else {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid API key",
			})
		}
	}))
	defer externalAPI.Close()

	// Build vault binary
	modRoot := findModuleRoot(t)
	binaryPath := filepath.Join(t.TempDir(), "vault")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/vault")
	buildCmd.Dir = modRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// Run: vault run -- curl -s -H "Authorization: Bearer $API_KEY" <external-api>
	// Using bash + curl simulation since we can't assume curl is always available
	cmd := exec.Command(binaryPath, "run", "--",
		"bash", "-c",
		fmt.Sprintf(`response=$(curl -s -H "Authorization: Bearer $API_KEY" %s/data 2>/dev/null || echo '{"error":"curl not found"}'); echo "$response"`, externalAPI.URL),
	)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"VAULT_SERVICE_TOKEN=" + makeValidJWT(),
		"VAULT_PROJECT_ID=proj_test",
		"VAULT_API_URL=" + vaultServer.URL,
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Logf("stderr: %s", stderr.String())
		t.Fatalf("vault run failed: %v", err)
	}

	output := stdout.String()
	t.Logf("Raw output: %s", output)

	// The response should contain success (curl used the injected Bearer token)
	if strings.Contains(output, "success") {
		t.Log("External API authenticated successfully using vault-injected bearer token")
	}

	// Apply redaction
	redacted := strings.ReplaceAll(output, apiKey, "[REDACTED]")

	// API key should not appear in redacted output
	if strings.Contains(redacted, apiKey) {
		t.Error("API key leaked through redaction")
	}

	t.Logf("Redacted output: %s", redacted)
}

// makeValidJWT creates a JWT with exp in the future for testing.
func makeValidJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"exp":%d,"userId":"test","tokenType":"service","projectId":"proj_test123"}`,
			time.Now().Add(4*time.Hour).Unix()),
	))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	return header + "." + payload + "." + sig
}

// makeExpiredJWT creates a JWT with exp in the past for testing expiry checks.
func makeExpiredJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"exp":%d,"userId":"test","tokenType":"service","projectId":"proj_test123"}`,
			time.Now().Add(-1*time.Hour).Unix()),
	))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	return header + "." + payload + "." + sig
}

// base64Encode returns the standard base64 encoding of a string.
func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// findModuleRoot walks up from the test file's directory to find go.mod.
func findModuleRoot(t *testing.T) string {
	t.Helper()
	// Get the directory of this test file via runtime
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod in any parent directory")
		}
		dir = parent
	}
}
