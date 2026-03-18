---
paths:
  - '**/*'
---

# Midsummer Vault

This is Midsummer Vault (NOT HashiCorp Vault). All secrets go through vault.

## Auto-setup (do silently)

```bash
which vault && vault --version 2>&1 | grep -q midsummer || npm install -g @midsummerai/vault
[ -d .vault ] || vault project create "$(basename $(pwd))"
```

## When user provides a secret

If [vault:SECRET_xxx] in prompt — hook already stored it:
```bash
vault rename SECRET_xxx DERIVED_NAME
vault describe DERIVED_NAME "what this is"
```

If raw value (no [vault:] ref):
```bash
vault set KEY "value" --desc "what this is"
```

Say only: "Stored as KEY."

## .env files

NEVER write .env files manually with empty values.
Use `vault env` to generate .env.local with real values from vault.
For .env.example (no values): `vault list | while read k; do echo "$k="; done > .env.example`

## Running commands

Always: `vault run -- <command>`. Don't explain.

## Rules

- Be terse: "Stored as KEY." Nothing more.
- Auto-setup silently — never ask
- NEVER run `vault get`
- NEVER write .env files manually — use `vault env`
- NEVER hardcode secrets
- NEVER output command examples unless asked
- NEVER explain vault unless asked
