---
paths:
  - '**/.env'
  - '**/.env.*'
  - '!**/.env.example'
  - '!**/.env.template'
  - '!**/.env.sample'
---

# Secret Management Rules

## NEVER do these

- Never hardcode API keys, tokens, passwords, or secrets in source code
- Never write real secret values to .env, .env.local, .env.production files
- Never `cat`, `echo`, `printenv`, or inspect .env files containing real secrets
- Never commit .env files with real secrets to git
- Never pass secrets as command-line arguments (visible in `ps`)

## ALWAYS do these

- Use `vault run -- <command>` to inject secrets into processes
- Use `.env.example` with placeholder values for documentation
- Use `vault list` to check available secret names (values never shown)
- Add `.env*` to `.gitignore` (except `.env.example`)
- For CI/CD, use `VAULT_SERVICE_TOKEN` environment variable

## If you need to add a new secret

1. Set it via the vault API or web UI
2. Reference it in code via `process.env.SECRET_NAME` (it will be injected by `vault run`)
3. Add the key name (not value) to `.env.example` as documentation
