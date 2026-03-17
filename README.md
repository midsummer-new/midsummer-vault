# Midsummer Vault

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
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
vault init                          # create encrypted vault
vault set STRIPE_KEY sk_live_...    # store a secret
vault set DATABASE_URL postgres://...
vault run -- npm run dev            # inject secrets into process
```

That's it. Your dev server has the secrets in its environment. The AI agent that launched it never saw the values.

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

### How it works

```
You type:  "use this stripe key sk_live_51OaJqDG..."

Hook intercepts -> stores in vault -> replaces in prompt

Model sees: "use this stripe key [vault:STRIPE_SECRET_c36b]"

Model asks: "What env var should this be?"
You:        "STRIPE_SECRET_KEY"
Model runs: vault rename STRIPE_SECRET_c36b STRIPE_SECRET_KEY

Model runs: vault run -- npm start
            (secrets injected, model never saw values)
```

### Detection layers

1. **Known prefixes** — 35+ services: Stripe, AWS, GitHub, OpenAI, Anthropic, Slack, SendGrid...
2. **Structural patterns** — JWTs, connection strings, private keys
3. **Shannon entropy** — catches unknown high-randomness strings (Redis tokens, custom API keys)
4. **Keyword proximity** — boosts confidence near "key", "secret", "token"

## CLI Commands

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

## How secrets are protected

**Encryption:** AES-256-GCM with random 12-byte IV per write. 256-bit key stored with 0600 permissions.

**Process isolation:** `vault run` uses `syscall.Exec` to replace the current process. There is no parent process to inspect — the agent process is gone.

**Prompt redaction:** The `UserPromptSubmit` hook scans your message before the model sees it. Detected secrets are auto-stored in the vault and replaced with `[vault:REF]` references.

**Output redaction:** `PostToolUse` hooks scan Bash command output and file contents for known vault values and replace them before the model sees the results.

## CI/CD

```yaml
# GitHub Actions
env:
  VAULT_KEY: ${{ secrets.VAULT_KEY }}
steps:
  - run: vault run -- npm test
```

## Team Sharing

```bash
# share the key via secure channel (1Password, encrypted DM)
cat .vault/key

# teammates add it to their project
echo "the-shared-key" > .vault/key
vault run -- npm start
```

## Plugin Structure

```
midsummer-vault/
  .claude-plugin/
    plugin.json           # plugin manifest
    marketplace.json      # marketplace catalog
  hooks/
    hooks.json            # hook registration (5 hooks)
    redact-secrets-from-prompt.js   # 4-layer detection + auto-store
    block-env-access.js             # blocks env inspection
    block-env-write.js              # blocks .env writes
    redact-bash-output.js           # output redaction
    redact-read-output.js           # file redaction
  skills/
    vault-setup/SKILL.md  # guided vault setup
  commands/
    vault-run.md           # /vault-run shortcut
    vault-check.md         # /vault-check shortcut
  rules/
    no-env-secrets.md      # auto-loaded when editing .env files
```

## License

Apache-2.0 — [Midsummer AI Labs AB](https://midsummer.new)
