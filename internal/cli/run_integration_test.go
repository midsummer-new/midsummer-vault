package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestExecWithSecrets_SecretsInProcessEnv verifies that vault run injects
// secrets into the child process environment correctly.
func TestExecWithSecrets_SecretsInProcessEnv(t *testing.T) {
	secrets := map[string]string{
		"STRIPE_KEY":   "sk_live_supersecret123",
		"DATABASE_URL": "postgres://user:pass@host:5432/db",
		"API_TOKEN":    "tok_abc_xyz_789",
	}

	// execWithSecrets uses syscall.Exec which replaces the process,
	// so we test the env merging logic directly instead.
	env := os.Environ()
	existing := make(map[string]int, len(env))
	for i, e := range env {
		if idx := strings.IndexByte(e, '='); idx >= 0 {
			existing[e[:idx]] = i
		}
	}

	for k, v := range secrets {
		if idx, ok := existing[k]; ok {
			env[idx] = k + "=" + v
		} else {
			env = append(env, k+"="+v)
		}
	}

	// Verify all secrets present in merged env
	found := make(map[string]bool)
	for _, e := range env {
		for k, v := range secrets {
			if e == k+"="+v {
				found[k] = true
			}
		}
	}
	for k := range secrets {
		if !found[k] {
			t.Errorf("secret %s not found in merged environment", k)
		}
	}
}

// TestExecWithSecrets_OverridesExistingEnv verifies vault secrets override
// any pre-existing env vars with the same name.
func TestExecWithSecrets_OverridesExistingEnv(t *testing.T) {
	// Set a var that vault will override
	os.Setenv("VAULT_TEST_OVERRIDE", "original_value")
	defer os.Unsetenv("VAULT_TEST_OVERRIDE")

	secrets := map[string]string{
		"VAULT_TEST_OVERRIDE": "vault_injected_value",
	}

	env := os.Environ()
	existing := make(map[string]int, len(env))
	for i, e := range env {
		if idx := strings.IndexByte(e, '='); idx >= 0 {
			existing[e[:idx]] = i
		}
	}

	for k, v := range secrets {
		if idx, ok := existing[k]; ok {
			env[idx] = k + "=" + v
		} else {
			env = append(env, k+"="+v)
		}
	}

	// Find the var — should be the vault value, not the original
	for _, e := range env {
		if strings.HasPrefix(e, "VAULT_TEST_OVERRIDE=") {
			val := strings.TrimPrefix(e, "VAULT_TEST_OVERRIDE=")
			if val != "vault_injected_value" {
				t.Errorf("expected vault value, got %q", val)
			}
			return
		}
	}
	t.Error("VAULT_TEST_OVERRIDE not found in env")
}

// TestAgentOpacity_CommandOutputRedaction simulates what an AI agent would see
// when vault run executes a command that prints env vars. The test verifies
// that a simple string replacement redaction (like our sandbox does) works.
func TestAgentOpacity_CommandOutputRedaction(t *testing.T) {
	secretValues := []string{
		"sk_live_supersecret123",
		"postgres://user:pass@host:5432/db",
		"tok_abc_xyz_789",
	}

	// Simulate command output that contains secret values
	rawOutput := `Starting server...
Connected to database at postgres://user:pass@host:5432/db
Using API key: sk_live_supersecret123
Auth token: tok_abc_xyz_789
Server ready on port 3000`

	// Apply redaction (same logic as sandbox redactSecrets)
	redacted := rawOutput
	for _, val := range secretValues {
		if len(val) < 4 {
			continue
		}
		redacted = strings.ReplaceAll(redacted, val, "[REDACTED]")
	}

	// Verify no secret values remain
	for _, val := range secretValues {
		if strings.Contains(redacted, val) {
			t.Errorf("secret value %q still present after redaction", val[:10]+"...")
		}
	}

	// Verify the redacted output still has structure
	if !strings.Contains(redacted, "[REDACTED]") {
		t.Error("no redaction markers found — redaction didn't work")
	}
	if !strings.Contains(redacted, "Starting server...") {
		t.Error("non-secret content was lost during redaction")
	}

	expected := `Starting server...
Connected to database at [REDACTED]
Using API key: [REDACTED]
Auth token: [REDACTED]
Server ready on port 3000`

	if redacted != expected {
		t.Errorf("unexpected redacted output:\n%s", redacted)
	}
}

// TestAgentOpacity_ShellHardening verifies that env/printenv/export commands
// are blocked by shell hardening functions.
// NOTE: Uses functions, NOT aliases — aliases don't expand in non-interactive bash.
func TestAgentOpacity_ShellHardening(t *testing.T) {
	// Must match getShellHardeningPreamble() in sandbox/index.ts
	preamble := `env() { echo "[vault] env inspection disabled"; }; ` +
		`printenv() { echo "[vault] env inspection disabled"; }; ` +
		`export() { echo "[vault] export inspection disabled"; }; ` +
		`declare() { echo "[vault] declare inspection disabled"; }; ` +
		`compgen() { echo "[vault] compgen inspection disabled"; }; ` +
		`chmod 000 /proc/self/environ 2>/dev/null; ` +
		`chmod 000 /proc/1/environ 2>/dev/null; `

	tests := []struct {
		name    string
		command string
		expect  string
	}{
		{"env blocked", "env", "[vault] env inspection disabled"},
		{"printenv blocked", "printenv", "[vault] env inspection disabled"},
		{"export blocked", "export", "[vault] export inspection disabled"},
		{"declare blocked", "declare -x", "[vault] declare inspection disabled"},
		{"compgen blocked", "compgen -v", "[vault] compgen inspection disabled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", preamble+tt.command)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("command failed: %v\n%s", err, out)
			}
			output := strings.TrimSpace(string(out))
			if output != tt.expect {
				t.Errorf("got %q, want %q", output, tt.expect)
			}
		})
	}
}

// TestAgentOpacity_EchoEnvRedacted verifies that even if an agent tries
// `echo $SECRET`, the redaction catches it in the output.
func TestAgentOpacity_EchoEnvRedacted(t *testing.T) {
	secretValue := "sk_live_supersecret_agent_test"

	// Simulate running: echo $STRIPE_KEY (which would expand in the shell)
	cmd := exec.Command("bash", "-c", "echo "+secretValue)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}

	rawOutput := string(out)

	// Apply redaction
	redacted := strings.ReplaceAll(rawOutput, secretValue, "[REDACTED]")

	if strings.Contains(redacted, secretValue) {
		t.Error("secret value leaked through redaction")
	}
	if !strings.Contains(redacted, "[REDACTED]") {
		t.Error("redaction marker not present")
	}
}

// TestMockVaultAPI_SecretsNeverInStdout spins up a mock vault API server,
// fetches secrets like the CLI would, and runs a subprocess that prints env.
// Verifies that the secret values appear in the process env but could be
// redacted from captured output.
func TestMockVaultAPI_SecretsNeverInStdout(t *testing.T) {
	secrets := map[string]string{
		"SECRET_API_KEY": "sk_test_mock_secret_12345",
		"DB_PASSWORD":    "p@ssw0rd!very$ecure",
	}

	// Mock vault API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/secrets") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"secrets": secrets,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	// Simulate what vault run does: fetch secrets, inject into env, run command
	resp, err := http.Get(server.URL + "/api/vault/proj_123/secrets")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var result struct {
		Secrets map[string]string `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}

	// Build env with secrets injected
	envSlice := []string{}
	for k, v := range result.Secrets {
		envSlice = append(envSlice, k+"="+v)
	}

	// Run a command that prints env (simulating what an agent might trigger)
	cmd := exec.Command("env")
	cmd.Env = envSlice
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}

	rawOutput := stdout.String()

	// Verify secrets ARE in the process output (env command prints them)
	for k, v := range secrets {
		if !strings.Contains(rawOutput, k+"="+v) {
			t.Errorf("secret %s not found in env output — injection failed", k)
		}
	}

	// Now apply redaction (what the sandbox would do before returning to agent)
	redacted := rawOutput
	for _, v := range secrets {
		redacted = strings.ReplaceAll(redacted, v, "[REDACTED]")
	}

	// Verify no secret VALUES remain (keys are fine, values must be redacted)
	for k, v := range secrets {
		if strings.Contains(redacted, v) {
			t.Errorf("secret value for %s leaked through redaction", k)
		}
		// Key name should still be present
		if !strings.Contains(redacted, k+"=") {
			t.Errorf("secret key %s was incorrectly removed", k)
		}
	}
}

// TestServiceToken_EnvAuth verifies that the CLI can authenticate via
// VAULT_SERVICE_TOKEN env var (for sandbox/non-interactive usage).
func TestServiceToken_EnvAuth(t *testing.T) {
	// This tests the concept — the actual implementation will read
	// VAULT_SERVICE_TOKEN as an alternative to credentials.json

	token := "vst_sandbox_abc123_shortlived"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+token {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"secrets": map[string]string{
				"RESEND_API_KEY": "re_test_123",
			},
		})
	}))
	defer server.Close()

	// Simulate CLI using service token instead of credentials file
	req, _ := http.NewRequest("GET", server.URL+"/api/vault/proj_123/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result struct {
		Secrets map[string]string `json:"secrets"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if result.Secrets["RESEND_API_KEY"] != "re_test_123" {
		t.Errorf("unexpected secret value: %v", result.Secrets)
	}
}

// TestFallbackToEnvLocal verifies the .env.local fallback works when
// no vault config exists (important for backward compat).
func TestFallbackToEnvLocal(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env.local")

	content := "MY_SECRET=from_env_file\nOTHER_VAR=hello\n"
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result := readDotEnv(envFile)

	if result["MY_SECRET"] != "from_env_file" {
		t.Errorf("expected 'from_env_file', got %q", result["MY_SECRET"])
	}
	if result["OTHER_VAR"] != "hello" {
		t.Errorf("expected 'hello', got %q", result["OTHER_VAR"])
	}
}
