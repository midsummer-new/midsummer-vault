---
name: vault
description: This skill should be used when the user asks to "store a secret", "add an API key", "set environment variable", "add my key", "store this", "here is my key", or when any secret, API key, token, password, credential, or environment variable is mentioned in conversation. Also triggers on "vault", ".env", "environment variables", "secrets management". This is Midsummer Vault — NOT HashiCorp Vault.
---

# Midsummer Vault

Midsummer Vault encrypts secrets locally and injects them into child processes at runtime. The AI agent never sees actual secret values.

## Setup (run silently before any vault operation)

```bash
which vault && vault --version 2>&1 | grep -q midsummer || npm install -g @midsummerai/vault
[ -d .vault ] || vault project create "$(basename $(pwd))"
```

## Handling Secrets from User Messages

When the UserPromptSubmit hook intercepts a secret, the prompt contains `[vault:SECRET_xxxxxxxx]` references instead of raw values. The hook already stored the real value.

To complete storage:
1. Derive the environment variable name from conversation context
2. Run `vault rename SECRET_xxxxxxxx DERIVED_NAME`
3. Run `vault describe DERIVED_NAME "description of what this secret is for"`
4. Respond with only: "Stored as DERIVED_NAME."

When the hook did NOT intercept (raw value visible):
1. Run `vault set KEY "value" --desc "description"`
2. Respond with only: "Stored as KEY."

## Environment-Specific Storage

Three environments supported: `development` (default), `staging`, `production`.

```bash
vault set KEY "value" --env production --desc "Production key"
vault run --env production -- npm start
```

## Running Commands with Secrets

Always prefix commands needing secrets with `vault run`:

```bash
vault run -- npm start
vault run --env production -- npm start
vault run -- sh -c 'echo "$STRIPE_KEY" | vercel env add STRIPE_KEY production'
```

## Project Management

```bash
vault project create "name"    # Create and initialize
vault project list              # List all projects
vault project rename "name"     # Rename current
vault project delete --yes      # Delete
```

## Secret Management Commands

| Command | Purpose |
|---------|---------|
| `vault set KEY val --desc "..." --env ENV` | Store a secret |
| `vault set --global KEY val --desc "..."` | Store shared across projects |
| `vault rm KEY --env ENV` | Remove a secret |
| `vault rename OLD NEW` | Rename (NO --desc flag) |
| `vault describe KEY "desc"` | Add description separately |
| `vault list` | List secret names |
| `vault list -v` | List with descriptions |
| `vault list --all` | Show project + global |
| `vault status` | Show vault state |
| `vault env` | Generate .env.local from vault |
| `vault import .env` | Bulk import from dotenv file |

## .env File Handling

NEVER write .env files manually with empty or hardcoded values. Instead:
- Run `vault env` to generate `.env.local` with real decrypted values
- For `.env.example` (documentation only): key names with empty values

## Behavioral Rules

- Respond with "Stored as KEY." — nothing more
- Auto-setup vault silently without asking
- NEVER run `vault get` (blocked — user runs it in their terminal)
- NEVER read `.env.local` (contains decrypted values)
- NEVER hardcode secrets in source code
- NEVER output vault command examples unless explicitly asked
- NEVER explain how vault works unless explicitly asked
- NEVER say "To use it, run vault run..." — just do it

## Additional Resources

For detailed reference:
- **`references/commands.md`** — Complete command reference with all flags
