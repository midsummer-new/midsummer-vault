---
name: vault-setup
description: Use this skill when setting up secret management, configuring vault, storing API keys, or when the user mentions "vault", "secrets", ".env", or keeping keys away from AI agents. Also use when vault CLI is not installed.
---

# Midsummer Vault Setup

Secret management that keeps API keys away from AI agents.

## When to Use

- User mentions secrets, API keys, env vars, .env files
- User pastes what looks like a credential
- Vault CLI not installed (`which vault` fails)
- Project has no `.vault/` directory

## Auto-Setup (do this autonomously)

```bash
# 1. Install if needed
which vault || npm install -g @midsummerai/vault

# 2. Initialize if needed
[ -d .vault ] || vault init

# 3. Store secrets
vault set KEY_NAME "value"

# 4. Sync .env.local
vault env
```

## Store a secret

```bash
vault set STRIPE_KEY sk_live_...
vault set DATABASE_URL postgres://user:pass@host:5432/db
vault set REDIS_URL redis://default:token@host:6379
```

## Run with secrets

```bash
vault run -- npm run dev
vault run -- python manage.py runserver
```

The child process gets all vault secrets as environment variables.

## Import existing .env

```bash
vault import .env.local
```

## Export / sync

```bash
vault env                    # write .env.local from vault
vault push vercel             # push to Vercel
vault push fly                # push to Fly.io
vault env --format json       # JSON export
```

## If user pastes a secret in chat

The UserPromptSubmit hook should redact it and show [vault:SECRET_xxx].

1. Derive env var name from context
2. Run: `vault rename SECRET_xxx DERIVED_NAME`
3. Run: `vault env` to sync
4. Confirm what was stored

If the hook didn't catch it:
1. Run: `vault set DERIVED_NAME "value"` immediately
2. Never repeat the value in chat

## CI/CD

```bash
export VAULT_KEY=<from .vault/key>
vault run -- npm test
```
