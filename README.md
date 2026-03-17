# Midsummer Vault

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/@midsummerai/vault)](https://www.npmjs.com/package/@midsummerai/vault)
[![GitHub stars](https://img.shields.io/github/stars/midsummer-new/midsummer-vault)](https://github.com/midsummer-new/midsummer-vault)

**Secret management for AI agents.** Keeps API keys away from LLMs.

Secrets are encrypted locally and injected into child processes at runtime. The AI agent never sees the actual values — not in the prompt, not in tool output, not in file contents.

## Quick Start

```bash
npm install -g @midsummerai/vault

vault init
vault set STRIPE_KEY sk_live_...
vault set DATABASE_URL postgres://...
vault run -- npm run dev
```

That's it. Your dev server has `STRIPE_KEY` and `DATABASE_URL` in its environment. The AI agent that launched it never saw the values.

## Claude Code Plugin

Install the plugin to automatically detect and redact secrets from your conversations:

```
/plugin marketplace add midsummer-new/midsummer-vault
/plugin install midsummer-vault@midsummer-vault
```

### What the plugin does

| Hook | When | What |
|------|------|------|
| **Secret detection** | You type a message | 4-layer scanner finds API keys, replaces with `[vault:REF]` before the model sees it |
| **Env blocking** | Agent runs `cat .env` or `printenv` | Blocks the command |
| **Write blocking** | Agent writes secrets to `.env` files | Blocks the write |
| **Bash redaction** | Agent command outputs a secret | Redacts known values from output |
| **Read redaction** | Agent reads a file with secrets | Redacts known values from content |

### How secret detection works

```
You type:  "use this stripe key sk_live_51OaJqDG..."

Hook detects Stripe key -> stores in vault -> replaces in prompt

Model sees: "use this stripe key [vault:STRIPE_SECRET_c36b]"

Model:     "I stored your Stripe key. I'll map it to STRIPE_SECRET_KEY."
           $ vault rename STRIPE_SECRET_c36b STRIPE_SECRET_KEY

Model:     $ vault run -- npm start     <- secrets injected, model never saw them
```

**Detection layers:**
1. **Known prefixes** -- 35+ services: Stripe, AWS, GitHub, OpenAI, Slack, SendGrid...
2. **Structural patterns** -- JWTs (`eyJ...`), connection strings (`postgres://...`), private keys
3. **Shannon entropy** -- catches unknown high-randomness strings (like Redis tokens)
4. **Keyword proximity** -- boosts confidence when "key", "secret", "token" appear nearby

## Commands

| Command | What |
|---------|------|
| `vault init` | Create encrypted vault in current directory |
| `vault set KEY value` | Store a secret |
| `vault get KEY` | Retrieve a secret |
| `vault rm KEY` | Remove a secret |
| `vault rename OLD NEW` | Map to an env var name |
| `vault list` | List secret names (not values) |
| `vault run -- cmd` | Run command with secrets injected |
| `vault import .env` | Bulk import from a .env file |
| `vault status` | Show vault state |

## How It Works

```
vault run -- npm start
      |
      +-- Reads .vault/secrets.enc (AES-256-GCM encrypted)
      +-- Decrypts with key from .vault/key (or VAULT_KEY env)
      +-- Merges secrets into environment
      +-- syscall.Exec replaces process
            |
            +-- npm start runs with STRIPE_KEY, DATABASE_URL, etc.
               The parent process (agent) is gone. No way to inspect.
```

**Encryption:** AES-256-GCM with random 12-byte IV per write. Key is 256-bit random, stored in `.vault/key` with `0600` permissions.

**Process isolation:** `syscall.Exec` replaces the current process entirely. There is no parent process for the agent to query. On Windows, `exec.Command` is used with stdin/stdout/stderr forwarding.

## CI/CD

No key file needed. Set `VAULT_KEY` as an environment variable:

```yaml
# GitHub Actions
env:
  VAULT_KEY: ${{ secrets.VAULT_KEY }}

steps:
  - run: vault run -- npm test
```

Or use the env prefix pattern (no vault CLI needed):

```yaml
env:
  VAULT_SECRET_STRIPE_KEY: ${{ secrets.STRIPE_KEY }}
  VAULT_SECRET_DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

## Team Sharing

Share the encryption key with your team via a secure channel:

```bash
cat .vault/key
# give this to teammates via 1Password, encrypted DM, etc.
```

Teammates clone the repo, create `.vault/key` with the shared key, and `vault run` works.

## Project Structure

```
.vault/
+-- .gitignore      # blocks everything in .vault/
+-- key             # 256-bit encryption key (0600 perms)
+-- secrets.enc     # AES-256-GCM encrypted secrets
```

## Providers

Built-in support for pulling secrets from external systems:

| Provider | How |
|----------|-----|
| **Local** (default) | `.vault/secrets.enc` |
| **AWS Secrets Manager** | Shells out to `aws secretsmanager get-secret-value` |
| **1Password** | Shells out to `op read op://vault/item/field` |
| **Env prefix** | `VAULT_SECRET_*` env vars stripped and injected |

## Install

**npm** (recommended):
```bash
npm install -g @midsummerai/vault
```

**Go:**
```bash
go install github.com/midsummer-new/midsummer-vault/cmd/vault@latest
```

**Script:**
```bash
curl -fsSL https://raw.githubusercontent.com/midsummer-new/midsummer-vault/main/install.sh | sh
```

## License

Apache-2.0 -- Midsummer AI Labs AB
