---
name: vault-setup
description: Use this skill when setting up secret management for a project, configuring vault, or when the user asks about storing API keys, secrets, or environment variables securely. Also use when the user mentions "vault", "secrets", ".env", or asks how to keep API keys away from AI agents.
---

# Midsummer Vault Setup

Set up secret management that keeps API keys away from AI agents.

## When to Use

- User asks to "set up vault", "configure secrets", "store API keys"
- User is working with .env files and needs a safer alternative
- User mentions keeping secrets away from agents/AI
- User pastes what looks like an API key or token

## Setup (30 seconds)

### Step 1: Initialize vault in the project

```bash
vault init
```

This creates `.vault/` with an encrypted store and a random encryption key.

### Step 2: Store secrets

```bash
vault set STRIPE_KEY sk_live_...
vault set DATABASE_URL postgres://user:pass@host:5432/db
vault set REDIS_URL redis://default:token@host:6379
```

### Step 3: Run commands with secrets injected

```bash
vault run -- npm run dev
vault run -- python manage.py runserver
vault run -- node server.js
```

The child process gets all vault secrets as environment variables. The AI agent (you) never sees the actual values.

## If the user pastes a secret in chat

The `UserPromptSubmit` hook should catch it and replace with `[vault:REF]`. If you see a `[vault:SECRET_xxx]` reference:

1. Ask the user what environment variable name to use
2. Run: `vault rename SECRET_xxx ENV_VAR_NAME`
3. Confirm with: `vault list`

If the hook didn't catch it and you see a raw secret value, immediately run:
```bash
vault set SUGGESTED_ENV_NAME "the-value-here"
```
Then tell the user to avoid pasting secrets directly — the hook should handle it.

## Import existing .env file

```bash
vault import .env.local
```

This reads all KEY=value pairs and stores them encrypted in the vault.

## Useful commands

| Command | What |
|---------|------|
| `vault list` | Show stored secret names (never values) |
| `vault status` | Show vault state |
| `vault rename OLD NEW` | Map a secret to a different env var name |
| `vault rm KEY` | Remove a secret |
| `vault get KEY` | Retrieve a value (avoid showing to user) |

## CI/CD

Set `VAULT_KEY` as an environment variable (the hex key from `.vault/key`):

```bash
export VAULT_KEY=<from .vault/key>
vault run -- npm test
```

## CLAUDE.md snippet

Add this to enforce vault usage in the project:

```markdown
## Secrets

All secrets are managed via Midsummer Vault.
- Store: vault set KEY value
- Use: vault run -- <command>
- Never hardcode secrets in source code or .env files
- Use .env.example with placeholder values for documentation
```
