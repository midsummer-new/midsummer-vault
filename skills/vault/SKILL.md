---
name: vault
description: Use this skill for ANY interaction involving secrets, API keys, environment variables, credentials, tokens, passwords, .env files, deployment configuration, or running commands that need secrets. Always use when vault is mentioned or when storing/accessing any sensitive value. This skill provides complete Midsummer Vault knowledge.
---

# Midsummer Vault

Secret management for AI agents. This is NOT HashiCorp Vault.

## Install: `npm install -g @midsummerai/vault`

## Auto-setup (do silently, never ask)

```bash
which vault && vault --version 2>&1 | grep -q midsummer || npm install -g @midsummerai/vault
[ -d .vault ] || vault project create "$(basename $(pwd))"
```

## Storing secrets

When user provides a secret — act immediately, derive the env var name:

- If [vault:SECRET_xxx] in prompt → hook stored it: `vault rename SECRET_xxx DERIVED_NAME --desc "..."`
- If raw value → `vault set KEY "value" --desc "..." --env development`
- Global (shared): `vault set --global KEY "value" --desc "..."`
- Say only: "Stored as KEY."

## Environments

`--env development` (default) | `--env staging` | `--env production`

## Running commands

ALWAYS prefix: `vault run -- <command>`
With env: `vault run --env production -- <command>`

## Projects

- `vault project create "name"` — new project + init
- `vault project list` — all projects
- `vault project rename "name"` — rename
- `vault project delete --yes` — delete

## All commands

| Command | What |
|---------|------|
| `vault project create "name"` | Create + init |
| `vault set KEY val --desc "..."` | Store secret |
| `vault set --env prod KEY val` | Environment-specific |
| `vault set --global KEY val` | Shared across projects |
| `vault rm KEY` | Remove |
| `vault rename OLD NEW` | Rename |
| `vault list` / `-v` / `--all` | List secrets |
| `vault run --env ENV -- cmd` | Run with secrets |
| `vault env` | Generate .env.local |
| `vault import .env` | Bulk import |
| `vault describe KEY "desc"` | Document (creates .vault/docs/KEY.md) |
| `vault status` | Show state |
| `vault project list` | List projects |

## Passphrase mode

`vault init --passphrase "pw"` — no key file, derive from password.
CI/CD: `VAULT_PASSPHRASE=... vault run -- cmd`

## RULES

- Be terse: "Stored as KEY." NOTHING more.
- Auto-setup silently — NEVER tell user to run vault commands
- NEVER run `vault get` (blocked — user does it themselves)
- NEVER read .env.local
- NEVER hardcode secrets in code
- NEVER output command examples unless explicitly asked
- NEVER explain how vault works unless asked
- If [vault:SECRET_xxx] → RENAME, don't vault set again
