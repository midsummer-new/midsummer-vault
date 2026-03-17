# Midsummer Vault

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/@midsummerai/vault)](https://www.npmjs.com/package/@midsummerai/vault)
[![GitHub stars](https://img.shields.io/github/stars/midsummer-new/midsummer-vault)](https://github.com/midsummer-new/midsummer-vault)

**Secret management for AI agents.** Keeps API keys away from LLMs.

Secrets are encrypted locally and injected into child processes at runtime. The AI agent never sees the actual values — not in the prompt, not in tool output, not in file contents.

## Install

```bash
npm install -g @midsummerai/vault
```

## Quick Start

```bash
vault init                          # create project vault
vault set STRIPE_KEY sk_live_...    # store a secret
vault run -- npm run dev            # inject secrets into process
```

Your dev server gets `STRIPE_KEY` in its environment. The AI agent that launched it never saw the value.

## Project vs Global Secrets

Each project gets its own `.vault/` — secrets don't leak between projects.

```bash
vault set STRIPE_KEY sk_live_...          # project only
vault set --global OPENAI_KEY sk-proj-... # shared across all projects

vault list                                # project secrets
vault list --all                          # both, shows overrides

vault run -- npm start                    # merges both (project wins)
```

## Claude Code Plugin

Automatically detects and redacts secrets from your conversations:

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

### How it works

```
You type:  "use this stripe key sk_live_51OaJqDG..."

Hook intercepts -> stores in vault -> replaces in prompt

Model sees: "use this stripe key [vault:STRIPE_SECRET_c36b]"
Model runs: vault rename STRIPE_SECRET_c36b STRIPE_SECRET_KEY
Model runs: vault run -- npm start  (secrets injected, never saw values)
```

### Detection layers

1. **Known prefixes** — 35+ services: Stripe, AWS, GitHub, OpenAI, Anthropic, Slack, SendGrid...
2. **Structural patterns** — JWTs, connection strings, private keys
3. **Shannon entropy** — catches unknown high-randomness strings
4. **Keyword proximity** — boosts confidence near "key", "secret", "token"

## Commands

| Command | What |
|---------|------|
| `vault init` | Create project vault |
| `vault init --global` | Create shared vault (~/.vault/) |
| `vault set KEY value` | Store secret (project) |
| `vault set --global KEY value` | Store secret (shared) |
| `vault get KEY` | Retrieve (checks project, then global) |
| `vault rm KEY` | Remove |
| `vault rename OLD NEW` | Rename / map to env var |
| `vault list` | Project secrets |
| `vault list --all` | Project + global |
| `vault run -- cmd` | Run with all secrets injected |
| `vault env` | Generate .env.local from vault |
| `vault import .env` | Bulk import |
| `vault status` | Show both vaults |

## How secrets are protected

**Encryption:** AES-256-GCM with random 12-byte IV per write. 256-bit key with 0600 permissions.

**Process isolation:** `vault run` replaces the process via `syscall.Exec`. No parent process to inspect.

**Project scoping:** `.vault/` lookup stops at the git root. Secrets never leak between projects.

**Prompt redaction:** Secrets in your messages are caught and replaced with `[vault:REF]` before the model sees them.

**Output redaction:** Known vault values are stripped from command output and file contents.

## CI/CD

```yaml
env:
  VAULT_KEY: ${{ secrets.VAULT_KEY }}
steps:
  - run: vault run -- npm test
```

## License

MIT
