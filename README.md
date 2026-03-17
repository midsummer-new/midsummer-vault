# Vault — Secret Management for AI Agents

Vault keeps API keys away from AI agents by encrypting secrets locally and injecting them into child processes at runtime. The agent never sees the values.

```
vault init                          # create local vault
vault set STRIPE_KEY sk_live_...    # encrypt and store
vault run -- npm run dev            # inject secrets into process env
```

Secrets are encrypted at rest with AES-256-GCM. The encryption key stays on your machine (or in your CI environment). The agent launches processes through `vault run` but never has access to the decrypted values.

## Install

```bash
# npm (recommended — includes prebuilt binaries)
npm install -g @midsummerai/vault

# Go
go install github.com/Reichel1/midsummer/vault-cli/cmd/vault@latest
```

## Quick Start

```bash
# 1. Initialize a vault in your project
vault init
# => creates .vault/ with encrypted store and AES-256 key
# => outputs VAULT_KEY for CI/CD use

# 2. Store secrets
vault set STRIPE_KEY sk_live_abc123
vault set DATABASE_URL postgres://user:pass@localhost:5432/myapp

# 3. Run your app with secrets injected
vault run -- npm run dev
# => child process gets STRIPE_KEY and DATABASE_URL in its environment
# => vault process is replaced via syscall.Exec — no parent to inspect
```

## Commands

| Command | Description |
|---------|-------------|
| `vault init` | Create a new `.vault/` in the current directory |
| `vault set KEY value` | Encrypt and store a secret |
| `vault get KEY` | Decrypt and print a secret value |
| `vault rm KEY` | Remove a secret |
| `vault rename OLD NEW` | Rename a secret key |
| `vault list` | List secret names (not values) |
| `vault run -- <cmd>` | Run a command with secrets injected as env vars |
| `vault import <file>` | Import secrets from a `.env` file |
| `vault login` | Authenticate with a remote vault server |
| `vault pull` | Pull secrets from a remote server into `.env.local.vault` |

## How It Works

### Protection layers

**Layer 1: Process isolation** — `vault run` decrypts secrets and passes them to the child process via `syscall.Exec`, which replaces the current process image. There is no parent process left to inspect. The AI agent launches the command but never handles the secret values.

**Layer 2: Tool blocking (Claude Code plugin)** — Pre-tool-use hooks intercept shell commands that would read secrets (`cat .env`, `printenv`, `echo $API_KEY`, `env | grep`) and block them before execution. Write hooks prevent the agent from saving secrets to files.

**Layer 3: Output redaction** — If a child process prints a secret value (e.g., in an error message), the hook framework can redact it before the model sees the output.

### What vault stores

```
.vault/
  key             # 64-char hex AES-256 key (chmod 0600)
  secrets.enc     # AES-256-GCM encrypted JSON blob
  .gitignore      # auto-generated, ignores everything in .vault/
```

The key file and encrypted store are automatically git-ignored. The encrypted store uses a random 12-byte IV per write, so the ciphertext changes even when secrets don't.

## Claude Code Plugin

Install the Claude Code hooks to block AI agents from inspecting secrets:

```bash
claude plugin install midsummer-vault
```

This adds hooks that:

- **PreToolUse (Bash)**: Blocks `cat .env*`, `printenv`, `env`, `echo $SECRET_*` and similar commands
- **PreToolUse (Write)**: Blocks writing files that contain secret values
- **UserPromptSubmit**: Warns if the user pastes something that looks like an API key

## CI/CD

In CI, set the `VAULT_KEY` environment variable instead of checking in the key file:

```yaml
# GitHub Actions
env:
  VAULT_KEY: ${{ secrets.VAULT_KEY }}

steps:
  - run: vault run -- npm test
```

Vault reads the key from `VAULT_KEY` when the env var is present, falling back to `.vault/key` for local development.

Alternatively, skip the encrypted store entirely and use the `VAULT_SECRET_` prefix pattern:

```yaml
env:
  VAULT_SECRET_STRIPE_KEY: ${{ secrets.STRIPE_KEY }}
  VAULT_SECRET_DATABASE_URL: ${{ secrets.DATABASE_URL }}

steps:
  - run: vault run -- npm test
    # vault strips the prefix: STRIPE_KEY, DATABASE_URL
```

## Team Sharing

Three options for sharing secrets across a team:

**Share the key file** — Copy `.vault/key` to teammates via a secure channel (1Password, encrypted message). Everyone decrypts the same `secrets.enc`.

**VAULT_KEY env var** — Each developer sets `VAULT_KEY` in their shell profile. Same effect, no file to manage.

**Vault server** — Run a centralized vault server for teams that need access control, audit logs, and shared secret management:

```bash
vault login --api-url https://vault.internal.company.com
vault run -- npm run dev
```

## Provider Interface

Vault supports pluggable secret backends through the `Provider` interface:

```go
type Provider interface {
    GetAll() (map[string]string, error)
    List() ([]string, error)
}
```

Built-in providers:

| Provider | Backend | How it works |
|----------|---------|-------------|
| `Store` (default) | Local `.vault/secrets.enc` | AES-256-GCM encrypted file |
| `EnvProvider` | Environment variables | Reads `VAULT_SECRET_*` prefix |
| `AWSSecretsManagerProvider` | AWS Secrets Manager | Shells out to `aws` CLI |
| `OnePasswordProvider` | 1Password | Shells out to `op` CLI |

Enterprise teams can implement the `Provider` interface to wrap any secret backend (HashiCorp Vault, Azure Key Vault, GCP Secret Manager, Doppler, etc.) without changing application code.

## License

Apache-2.0
