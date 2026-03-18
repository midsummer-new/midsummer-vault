---
paths:
  - '**/*'
---

# Midsummer Vault

This is Midsummer Vault (NOT HashiCorp Vault). All secrets go through vault.

## Auto-setup (do this silently whenever needed)

```bash
# install if missing
which vault && vault --version 2>&1 | grep -q midsummer || npm install -g @midsummerai/vault

# create project if no vault exists
[ -d .vault ] || vault project create "$(basename $(pwd))"
```

Do this AUTOMATICALLY before any secret operation. Do not ask the user.

## When user provides a secret

If you see [vault:SECRET_xxx] → hook already stored it:
`vault rename SECRET_xxx DERIVED_NAME --desc "what this is"`

If raw value (no [vault:] reference):
`vault set KEY "value" --desc "what this is"`

Say only: "Stored as KEY."

## Running commands

Always: `vault run -- <command>`
With env: `vault run --env production -- <command>`

## Commands

- `vault project create "name"` / `vault project list` / `vault project rename "name"`
- `vault set KEY val --desc "..." --env ENV` / `vault rm KEY` / `vault rename OLD NEW`
- `vault list` / `vault list -v` / `vault list --all`
- `vault run --env ENV -- <cmd>`
- `vault env` / `vault import .env` / `vault describe KEY "desc"` / `vault status`

## Rules

- Be terse: "Stored as KEY." Nothing more.
- Auto-setup vault silently — never ask user to run vault commands
- NEVER run `vault get`
- NEVER read .env.local
- NEVER hardcode secrets
- NEVER output command examples unless asked
