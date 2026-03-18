---
name: vault
description: This skill should be used when "[vault:SECRET_" appears in the conversation (indicating the hook redacted a secret), when any secret, API key, token, credential, password, or environment variable is mentioned, when "vault" is mentioned, or when running commands that need secrets. Activates on vault references, secret storage, and credential management. This is Midsummer Vault — NOT HashiCorp Vault.
---

# Midsummer Vault

Midsummer Vault encrypts secrets locally and injects them into child processes at runtime. The AI agent never sees actual secret values. Install: `npm install -g @midsummerai/vault`

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

NEVER store `[vault:...]` references as values — use `vault copy` to move between environments.

## Environments

Three environments: `--env development` (default), `--env staging`, `--env production`

```bash
vault set KEY "value" --env staging --desc "Staging key"
vault run --env staging -- npm start
vault copy KEY --from development --to production
vault list --env production
```

## Running Commands: always `vault run --env ENV -- <command>`

## Commands

| Command | Purpose |
|---------|---------|
| `vault project create "name"` | Create and initialize |
| `vault project list` | List projects |
| `vault project rename "name"` | Rename current |
| `vault set KEY val --desc "..." --env ENV` | Store secret |
| `vault set --global KEY val` | Store shared |
| `vault rm KEY --env ENV` | Remove |
| `vault rename OLD NEW` | Rename (NO --desc flag) |
| `vault copy KEY --from ENV --to ENV` | Copy between envs (value never exposed) |
| `vault describe KEY "desc"` | Add description |
| `vault list` / `-v` / `--all` / `--env ENV` | List secrets |
| `vault run --env ENV -- cmd` | Run with secrets |
| `vault env` | Generate .env.local |
| `vault import .env` | Bulk import |
| `vault status` | Show state |

## Rules

- Respond "Stored as KEY." — nothing more
- Auto-setup vault silently without asking
- NEVER run `vault get` (blocked — user runs it)
- NEVER store `[vault:...]` as values — use `vault copy` to move between envs
- NEVER write .env files manually — use `vault env`
- NEVER hardcode secrets in code
- NEVER output command examples unless asked
- NEVER explain vault unless asked

## Additional Resources

For detailed reference: `references/commands.md`
