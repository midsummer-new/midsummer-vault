---
paths:
  - '**/*'
---

# Midsummer Vault

This project uses Midsummer Vault for secret management.

## Setup (if vault not installed)

```bash
which vault || npm install -g @midsummerai/vault
vault init  # if .vault/ doesn't exist
```

## Commands

- `vault list` — list stored secret names (never shows values)
- `vault status` — show vault state
- `vault set KEY value` — store a secret
- `vault get KEY` — retrieve a secret value
- `vault rename OLD NEW` — rename / map to env var
- `vault rm KEY` — delete a secret
- `vault run -- <command>` — run with secrets injected as env vars
- `vault import .env` — bulk import from .env file
- `vault env` — generate .env.local from vault
- `vault push vercel` — push secrets to Vercel
- `vault push fly` — push secrets to Fly.io

## When a user provides a secret

Act IMMEDIATELY. Do NOT ask what to name it.

1. Check: `which vault || npm install -g @midsummerai/vault`
2. Check: if no `.vault/` directory, run `vault init`
3. Derive env var name from context ("redis key" → REDIS_KEY, "stripe" → STRIPE_SECRET_KEY)
4. If [vault:SECRET_xxx] reference: `vault rename SECRET_xxx DERIVED_NAME`
5. If raw value: `vault set DERIVED_NAME "value"`
6. Sync: `vault env`
7. Confirm: "Stored as REDIS_KEY. Use: vault run -- <command>"
8. NEVER echo the secret value

## Rules

- NEVER hardcode secrets in source code or .env files
- NEVER use cat .env, printenv, echo $SECRET
- ALWAYS use `vault run -- <command>` to inject secrets
- After any change, run `vault env` to sync .env.local
