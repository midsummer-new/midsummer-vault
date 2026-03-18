package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/midsummer-new/midsummer-vault/internal/api"
	"github.com/midsummer-new/midsummer-vault/internal/auth"
	"github.com/midsummer-new/midsummer-vault/internal/config"
	"github.com/midsummer-new/midsummer-vault/internal/store"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run [--env ENV] -- <command> [args...]",
	Short: "Run a command with vault secrets injected as env vars",
	Long: `Reads secrets from the local vault (.vault/) or a remote server and injects
them into the child process environment.

Use --env to select which environment's secrets to inject (default: development).

Examples:
  vault run -- npm start
  vault run --env production -- npm start
  vault run --env staging -- node server.js`,
	Args: cobra.MinimumNArgs(1),
	// Prevent cobra from parsing flags after --
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// manually parse --env flag before the "--" separator
		env := store.DefaultEnv
		var cleanArgs []string
		for i := 0; i < len(args); i++ {
			if args[i] == "--env" && i+1 < len(args) {
				env = args[i+1]
				i++ // skip the value
				continue
			}
			if strings.HasPrefix(args[i], "--env=") {
				env = strings.TrimPrefix(args[i], "--env=")
				continue
			}
			cleanArgs = append(cleanArgs, args[i])
		}
		args = cleanArgs

		// Strip leading "--" if present
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		if len(args) == 0 {
			return fmt.Errorf("no command specified")
		}

		secrets := fetchSecretsOrFallback(env)
		return execWithSecrets(args, secrets)
	},
}

// fetchSecretsOrFallback resolves secrets with this priority:
// 1. VAULT_SERVICE_TOKEN env (headless sandbox)
// 2. Auto-pull from server if sync is configured (keeps local cache fresh)
// 3. Local vault + global vault merged for the given env (local wins on conflict)
// 4. Remote server (.vault.toml + credentials.json)
// 5. .env.local fallback
func fetchSecretsOrFallback(env string) map[string]string {
	// 1. Service token (headless sandbox mode)
	if secrets := fetchViaServiceToken(); secrets != nil {
		return secrets
	}

	// 2. Auto-pull from server if sync is configured (keeps local cache fresh)
	if cfg := store.LoadSyncConfig(); cfg.Enabled {
		if store.NeedsPull(cfg, env) {
			if err := store.Pull(cfg, env); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ sync pull failed: %v (using local)\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "  ↓ updated from server\n")
			}
		}
	}

	// 3. Local vault + global vault merged — local wins on conflict
	hasLocal := store.Exists()
	hasGlobal := store.GlobalExists()

	if hasLocal || hasGlobal {
		merged := make(map[string]string)

		// load global first (lower priority)
		if hasGlobal {
			gs, err := store.OpenGlobalWithEnv(env)
			if err != nil {
				fmt.Fprintf(os.Stderr, "vault: global store error: %v\n", err)
			} else {
				secrets, err := gs.GetAll()
				if err != nil {
					fmt.Fprintf(os.Stderr, "vault: global decrypt error: %v\n", err)
				} else {
					for k, v := range secrets {
						merged[k] = v
					}
				}
			}
		}

		// load local on top (higher priority, overwrites global)
		if hasLocal {
			ls, err := store.OpenWithEnv(env)
			if err != nil {
				fmt.Fprintf(os.Stderr, "vault: local store error: %v\n", err)
			} else {
				secrets, err := ls.GetAll()
				if err != nil {
					fmt.Fprintf(os.Stderr, "vault: local decrypt error: %v\n", err)
				} else {
					for k, v := range secrets {
						merged[k] = v
					}
				}
			}
		}

		if len(merged) > 0 {
			return merged
		}
	}

	// 4. Remote server (.vault.toml + credentials.json)
	projectCfg, err := config.LoadProjectConfig()
	if err != nil || projectCfg == nil {
		// no .vault.toml and no local vault — fall back to .env.local
		return readDotEnv(".env.local")
	}

	creds, err := config.LoadCredentials()
	if err != nil || creds == nil {
		fmt.Fprintf(os.Stderr, "vault: not logged in, run `vault login` — using .env.local fallback\n")
		return readDotEnv(".env.local")
	}

	if projectCfg.Vault.APIURL != "" {
		creds.APIURL = projectCfg.Vault.APIURL
	}

	client, err := api.NewClient(creds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vault: auth error — using .env.local fallback\n")
		return readDotEnv(".env.local")
	}

	secrets, err := client.GetSecrets(projectCfg.Vault.ProjectID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vault: API error: %v — using .env.local fallback\n", err)
		return readDotEnv(".env.local")
	}

	return secrets
}

// fetchViaServiceToken uses VAULT_SERVICE_TOKEN + VAULT_PROJECT_ID + VAULT_API_URL
// env vars for headless authentication (Modal sandboxes). Returns nil if not configured.
func fetchViaServiceToken() map[string]string {
	serviceToken := os.Getenv("VAULT_SERVICE_TOKEN")
	projectID := os.Getenv("VAULT_PROJECT_ID")
	apiURL := os.Getenv("VAULT_API_URL")

	if serviceToken == "" || projectID == "" {
		return nil
	}

	// Hard-fail on expired service tokens instead of silently falling back to empty env
	if auth.IsTokenExpired(serviceToken) {
		fmt.Fprintf(os.Stderr, "vault: service token expired — request a new one\n")
		os.Exit(1)
	}

	if apiURL == "" {
		apiURL = defaultAPIURL
	}

	creds := &config.Credentials{
		APIURL:      apiURL,
		AccessToken: serviceToken,
	}

	client, err := api.NewClientDirect(creds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vault: service token auth error: %v\n", err)
		return nil
	}

	secrets, err := client.GetSecrets(projectID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vault: service token API error: %v\n", err)
		return nil
	}

	return secrets
}

// execWithSecrets replaces the current process with the command, merging
// vault secrets into the environment. Vault secrets override existing env vars.
func execWithSecrets(args []string, secrets map[string]string) error {
	binary, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("command not found: %s", args[0])
	}

	// Build merged environment: current env + vault secrets (vault wins)
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

	// platform-specific exec (syscall.Exec on unix, exec.Command on windows)
	return execProcess(binary, args, env)
}

// readDotEnv reads a .env file and returns key=value pairs.
// Returns empty map if file doesn't exist.
func readDotEnv(path string) map[string]string {
	result := make(map[string]string)

	f, err := os.Open(path)
	if err != nil {
		return result
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		// Strip surrounding quotes
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		result[key] = value
	}

	return result
}
