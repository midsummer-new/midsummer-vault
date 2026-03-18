---
paths:
  - '**/*'
---

# Midsummer Vault

Secrets managed through vault. Be brief — just use it.

## Setup

```bash
which vault || npm install -g @midsummerai/vault
[ -d .vault ] || vault init
```

## Storing secrets

Act immediately. Derive env var name from context.

```bash
vault set KEY "value" --desc "what this is" --env development
vault set --global OPENAI_KEY "value" --desc "shared OpenAI key"
vault set --env production STRIPE_KEY "value" --desc "Stripe live key"
```

## Running with secrets

```bash
vault run -- npm start
vault run --env production -- npm start
```

## Environments

`--env development` (default), `--env staging`, `--env production`

## Commands

- `vault set KEY value --desc "..." --env ENV`
- `vault rm KEY --env ENV`
- `vault rename OLD NEW`
- `vault list` / `vault list -v` / `vault list --all`
- `vault run --env ENV -- <command>`
- `vault env` (sync .env.local)
- `vault import .env`
- `vault describe KEY "description"`
- `vault status`

## Rules

- NEVER run `vault get` (exposes values — user runs it themselves)
- NEVER hardcode secrets in code
- NEVER cat .env, printenv, echo $SECRET
- ALWAYS use `vault run --` for commands needing secrets
- Be terse: "Stored as REDIS_KEY." is enough
