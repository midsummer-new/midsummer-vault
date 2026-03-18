---
name: vault-setup
description: Use this skill when setting up secret management, configuring vault, storing API keys, or when the user mentions "vault", "secrets", ".env", or keeping keys away from AI agents. Also use when vault CLI is not installed.
---

# Midsummer Vault Setup

Secret management that keeps API keys away from AI agents.

## Auto-Setup

```bash
which vault || npm install -g @midsummerai/vault
[ -d .vault ] || vault init
```

Or with passphrase (no key file to lose):
```bash
vault init --passphrase "your secure password"
```

## Store secrets

```bash
vault set STRIPE_KEY sk_live_... --desc "Stripe live key"
vault set DATABASE_URL postgres://... --desc "Production DB"
vault set --env production STRIPE_KEY sk_live_prod... --desc "Stripe production"
vault set --global OPENAI_KEY sk-... --desc "Shared OpenAI key"
```

Always add `--desc` when you know what the secret is for.

## Run with secrets

```bash
vault run -- npm run dev
vault run --env production -- npm start
```

## Environments

- `--env development` (default)
- `--env staging`
- `--env production`

Each environment has separate secrets. Use the right one.

## Import existing .env

```bash
vault import .env.local
```

## Document secrets

```bash
vault describe STRIPE_KEY "Stripe live key. From dashboard.stripe.com/apikeys"
```

Creates `.vault/docs/STRIPE_KEY.md` — committable, no secret values.

## If user pastes a secret in chat

The UserPromptSubmit hook should redact it. If you see [vault:SECRET_xxx]:

1. Derive env var name from context
2. `vault rename SECRET_xxx DERIVED_NAME`
3. Confirm what was stored

If hook didn't catch it:
1. `vault set DERIVED_NAME "value" --desc "what this is"`
2. Never repeat the value

## Passphrase vs key file

- **Key file** (default): `.vault/key` — back it up or lose everything
- **Passphrase**: `vault init --passphrase "pw"` — no file, remember the password
- **CI/CD**: `VAULT_KEY` or `VAULT_PASSPHRASE` env var

## Useful commands

| Command | What |
|---------|------|
| `vault list` | Secret names |
| `vault list -v` | Names + descriptions |
| `vault list --all` | Project + global |
| `vault status` | Vault state |
| `vault run -- cmd` | Inject secrets |
| `vault env` | Generate .env.local |
| `vault describe KEY "desc"` | Document a secret |

## Rules

- NEVER run `vault get` (user runs it themselves)
- NEVER hardcode secrets
- NEVER cat .env, printenv, echo $SECRET
- Be terse: "Stored as KEY." is enough
