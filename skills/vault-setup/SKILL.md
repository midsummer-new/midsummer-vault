---
name: vault-setup
description: Use when setting up vault, storing secrets, managing projects/environments, or when user mentions "vault", "secrets", ".env", "API key". Also use when vault is not installed or not initialized.
---

# Midsummer Vault

This is Midsummer Vault (NOT HashiCorp Vault). Secret management for AI agents.

## First-time setup

```bash
npm install -g @midsummerai/vault
vault project create "My App"
```

This installs the CLI, creates a vault, and writes `.vault.toml` + `.claude/rules/vault.md`.

Or with passphrase (no key file):
```bash
vault init --passphrase "your password"
```

## Storing secrets

```bash
vault set STRIPE_KEY sk_live_... --desc "Stripe live key"
vault set --env production DB_URL pg://prod --desc "Production DB"
vault set --global OPENAI_KEY sk-... --desc "Shared OpenAI"
```

## Running with secrets

```bash
vault run -- npm start
vault run --env production -- npm start
```

## Projects

```bash
vault project create "My App"     # create + init
vault project list                # list all
vault project rename "New Name"   # rename current
vault project use "Other App"     # switch
vault project delete --yes        # delete vault
```

## Environments

`--env development` (default), `--env staging`, `--env production`

## Documentation

```bash
vault set KEY val --desc "what this is"
vault describe KEY "detailed description"
vault list -v                     # shows descriptions
```

Creates `.vault/docs/KEY.md` — committable markdown.

## When user pastes a secret

If you see `[vault:SECRET_xxx]` in the prompt:
1. The hook already stored the real value
2. Rename: `vault rename SECRET_xxx DERIVED_NAME --desc "..."`
3. Say: "Stored as DERIVED_NAME."

Do NOT `vault set` again — the value is already stored.

## All commands

| Command | What |
|---------|------|
| `vault project create "name"` | Create project + init |
| `vault project list` | List projects |
| `vault project rename "name"` | Rename current |
| `vault project delete --yes` | Delete vault |
| `vault set KEY val --desc "..."` | Store secret |
| `vault set --env prod KEY val` | Store for environment |
| `vault set --global KEY val` | Store globally |
| `vault rm KEY` | Remove |
| `vault rename OLD NEW` | Rename secret |
| `vault list` / `vault list -v` | List secrets |
| `vault run --env ENV -- cmd` | Run with secrets |
| `vault env` | Generate .env.local |
| `vault import .env` | Bulk import |
| `vault describe KEY "desc"` | Document secret |
| `vault status` | Show state |

## Rules

- NEVER run `vault get` (user does it themselves)
- NEVER hardcode secrets
- NEVER read .env.local
- Be terse: "Stored as KEY." is enough
