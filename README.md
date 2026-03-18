# Midsummer Vault

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/@midsummerai/vault)](https://www.npmjs.com/package/@midsummerai/vault)

**Secret management for AI agents.** Keeps API keys away from LLMs.

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

## Passphrase Mode (no key file to lose)

```bash
vault init --passphrase "my secure password"
VAULT_PASSPHRASE="my secure password" vault run -- npm start
```

No `.vault/key` file. Key derived from your passphrase via Argon2id.

## Environments

```bash
vault set STRIPE_KEY sk_test_... --env development
vault set STRIPE_KEY sk_live_... --env production
vault run --env production -- npm start
```

## Project vs Global Secrets

```bash
vault set STRIPE_KEY sk_live_...          # project only
vault set --global OPENAI_KEY sk-proj-... # shared across all projects
vault run -- npm start                    # merges both (project wins)
```

## Secret Documentation

```bash
vault set STRIPE_KEY sk_live_... --desc "Stripe live key for payments"
vault describe STRIPE_KEY "From dashboard.stripe.com/apikeys"
vault list -v                             # shows descriptions
```

Creates `.vault/docs/STRIPE_KEY.md` — committable to git, no secret values.

## Claude Code Plugin

```
/plugin marketplace add midsummer-new/midsummer-vault
/plugin install midsummer-vault@midsummer-vault
```

5 hooks: secret detection in prompts, env blocking, write blocking, output redaction.

## Commands

| Command | What |
|---------|------|
| `vault init` | Create project vault |
| `vault init --passphrase "pw"` | Create with passphrase (no key file) |
| `vault set KEY value` | Store secret |
| `vault set --env prod KEY val` | Store for specific environment |
| `vault set --global KEY val` | Store globally (shared) |
| `vault get KEY` | Retrieve value |
| `vault rm KEY` | Remove |
| `vault rename OLD NEW` | Rename |
| `vault list` | List names |
| `vault list -v` | List with descriptions |
| `vault list --all` | Project + global |
| `vault run -- cmd` | Run with secrets injected |
| `vault env` | Generate .env.local |
| `vault import .env` | Bulk import |
| `vault describe KEY "desc"` | Document a secret (markdown) |
| `vault status` | Show vault state |

## Security

- **AES-256-GCM** encryption with random IV per write
- **Argon2id** key derivation for passphrase mode
- **Process isolation** via `syscall.Exec` (agent process replaced)
- **Project scoping** stops at git root (no cross-project leaks)
- **Prompt redaction** detects secrets before model sees them
- **Output redaction** strips values from command output

## CI/CD

```yaml
env:
  VAULT_KEY: ${{ secrets.VAULT_KEY }}
  # or for passphrase vaults:
  VAULT_PASSPHRASE: ${{ secrets.VAULT_PASSPHRASE }}
steps:
  - run: vault run -- npm test
```

## License

MIT
