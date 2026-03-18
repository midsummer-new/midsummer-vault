---
name: vault
description: Use for ANY interaction involving secrets, API keys, environment variables, credentials, tokens, passwords, .env files, or running commands that need secrets. Always use when storing/accessing sensitive values.
---

# Midsummer Vault

Secret management for AI agents. NOT HashiCorp Vault.
Install: `npm install -g @midsummerai/vault`

## Auto-setup (do silently, never ask)

```bash
which vault && vault --version 2>&1 | grep -q midsummer || npm install -g @midsummerai/vault
[ -d .vault ] || vault project create "$(basename $(pwd))"
```

## Storing secrets

When [vault:SECRET_xxx] in prompt (hook stored it):
```bash
vault rename SECRET_xxx DERIVED_NAME
vault describe DERIVED_NAME "what this is"
```

When raw value:
```bash
vault set KEY "value" --desc "what this is"
```

Say only: "Stored as KEY."

## .env files

NEVER write .env manually. Use:
- `vault env` → generates .env.local with real values
- For .env.example: names only, no values

## Commands

| Command | What |
|---------|------|
| `vault project create "name"` | Create + init |
| `vault project list` | List projects |
| `vault project rename "name"` | Rename current |
| `vault project delete --yes` | Delete |
| `vault set KEY val --desc "..."` | Store (add `--env prod` for production) |
| `vault set --global KEY val` | Shared across projects |
| `vault rm KEY` | Remove |
| `vault rename OLD NEW` | Rename secret (NO --desc flag) |
| `vault describe KEY "desc"` | Add description separately |
| `vault list` / `-v` / `--all` | List secrets |
| `vault run --env ENV -- cmd` | Run with secrets |
| `vault env` | Generate .env.local |
| `vault import .env` | Bulk import |
| `vault status` | Show state |

## Rules

- "Stored as KEY." NOTHING more.
- NEVER run `vault get`
- NEVER write .env files manually
- NEVER hardcode secrets
- NEVER output examples unless asked
- NEVER explain vault unless asked
