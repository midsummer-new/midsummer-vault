---
paths:
  - '**/*'
---

# Midsummer Vault

This project uses Midsummer Vault for secret management. ALWAYS use the vault CLI for secrets.

## Commands you MUST use

- `vault list` — list stored secret names (never shows values)
- `vault status` — show vault state (how many secrets, key source)
- `vault set KEY value` — store a new secret
- `vault get KEY` — retrieve a secret value
- `vault rename OLD NEW` — rename a secret / map to env var
- `vault rm KEY` — delete a secret
- `vault run -- <command>` — run a command with all secrets injected as env vars
- `vault import .env` — bulk import from a .env file
- `vault init` — initialize vault (if not already done)

## Rules

- NEVER hardcode secrets in source code or .env files
- NEVER use `cat .env`, `printenv`, `echo $SECRET` to inspect secrets
- ALWAYS use `vault run -- <command>` to inject secrets into processes
- If a user pastes a secret in chat, store it with `vault set KEY value`
- Use `vault list` to check what secrets are available
- Use `vault status` to check if vault is initialized
- Secrets are encrypted in `.vault/secrets.enc` — do not read this file directly
