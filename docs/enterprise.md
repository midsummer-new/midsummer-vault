# Enterprise Integration Guide

## How vault fits into your existing infrastructure

Vault is a **bridge** between your existing secret management and AI agents. It doesn't replace AWS Secrets Manager or HashiCorp Vault — it ensures secrets from those systems never enter the AI model's context.

## Integration Patterns

### Pattern 1: Local vault (small teams, solo developers)

```bash
vault init
vault set STRIPE_KEY sk_live_...
vault run -- claude        # Claude Code with secrets, secrets never in context
```

Best for: Individual developers, small teams, prototyping.

### Pattern 2: Env prefix (CI/CD, existing secret injection)

If your CI/CD already injects secrets (GitHub Actions, GitLab CI, AWS CodeBuild), use the `VAULT_SECRET_` prefix pattern:

```yaml
# GitHub Actions example
env:
  VAULT_SECRET_STRIPE_KEY: ${{ secrets.STRIPE_KEY }}
  VAULT_SECRET_DATABASE_URL: ${{ secrets.DATABASE_URL }}

steps:
  - run: vault run -- npm test
    # vault reads VAULT_SECRET_* vars, strips prefix, injects as STRIPE_KEY, DATABASE_URL
```

No vault server needed. No key file needed. Just prefix your existing secrets.

### Pattern 3: Vault server (teams, shared secrets)

Run the vault server for shared secret management:

```bash
# Self-hosted
docker run -d -p 8080:8080 \
  -e VAULT_ENCRYPTION_KEY=$(openssl rand -hex 32) \
  -e SESSION_SECRET=$(openssl rand -base64 48) \
  ghcr.io/midsummer-new/vault-server:latest

# Each developer
vault login --api-url https://vault.internal.company.com
vault run -- npm run dev
```

Best for: Teams of 5-50, shared development secrets.

### Pattern 4: Wrap your existing secret manager

Use vault as a thin wrapper around your existing infrastructure:

```bash
# AWS Secrets Manager → vault run
vault run --provider aws-sm --secret-id prod/api-keys -- npm run dev

# HashiCorp Vault → vault run
vault run --provider hcv --path secret/data/myapp -- npm run dev

# 1Password → vault run
vault run --provider 1password --vault "Development" -- npm run dev
```

(Provider integrations are on the roadmap. The Provider interface is extensible.)

## How AI agent protection works

### Layer 1: Process isolation (vault run)

```
┌─────────────────────────────────────────┐
│ AI Agent (Claude Code, Cursor, etc.)    │
│                                         │
│ Context window: NO secrets here         │
│                                         │
│ Runs: vault run -- npm run dev          │
│         │                               │
│         ▼                               │
│ ┌─────────────────────────────────┐     │
│ │ Child process (npm run dev)     │     │
│ │                                 │     │
│ │ Environment:                    │     │
│ │   STRIPE_KEY=sk_live_...       │     │
│ │   DATABASE_URL=postgres://...  │     │
│ │                                 │     │
│ │ (inherited via syscall.Exec)   │     │
│ └─────────────────────────────────┘     │
└─────────────────────────────────────────┘
```

The agent launches the process but never sees the values. `syscall.Exec` replaces the process image — there's no parent process to inspect.

### Layer 2: Tool blocking (Claude Code plugin hooks)

Even if an agent tries to inspect the environment:

| Agent attempts | Hook | Result |
|---------------|------|--------|
| `cat .env` | PreToolUse (Bash) | BLOCKED |
| `printenv` | PreToolUse (Bash) | BLOCKED |
| `echo $API_KEY` | PreToolUse (Bash) | BLOCKED |
| Write secrets to file | PreToolUse (Write) | BLOCKED |
| User pastes key in chat | UserPromptSubmit | WARNED (can't unsee) |

### Layer 3: Output redaction

If a child process outputs a secret value (e.g., in an error message), the agent framework can redact it before the model sees the output.

### What vault CANNOT protect against

Be honest with your security team:

1. **User pasting secrets in chat** — the model sees the prompt before any hook runs
2. **Secrets in source code** — if a developer commits `API_KEY="sk_live_..."` to git, the model will see it when reading files
3. **Model inference** — a model might guess a secret format or infer values from context
4. **Side channels** — timing attacks, error message patterns, etc.

Vault protects against the most common vector: the agent actively reading secrets from the environment or files.

## Compliance notes

### SOC 2
- Secrets encrypted at rest (AES-256-GCM)
- Key material stored with 0600 permissions
- No secrets in version control (.gitignore enforced)
- Audit logging available (vault server mode)

### GDPR
- No data leaves the machine (local mode)
- Server mode: data stays on your infrastructure
- No third-party services involved

### For your security team

Share this threat model:

| Threat | Mitigation | Residual risk |
|--------|-----------|---------------|
| AI reads .env files | PreToolUse hook blocks file reads | Low — hook must be installed |
| AI inspects env vars | Shell hardening blocks env/printenv | Low — only in sandboxed environments |
| User shares secret in chat | UserPromptSubmit warns | Medium — can't prevent model seeing prompt |
| Secret in source code | .gitignore + code review | Medium — depends on team discipline |
| Key file compromised | 0600 perms, VAULT_KEY for CI | Low — standard file security |
| Encrypted store brute forced | AES-256-GCM, 256-bit random key | Negligible |

## Team onboarding

### Step 1: Add vault to your project

```bash
# In your project root
vault init

# Set your development secrets
vault set STRIPE_KEY sk_test_...
vault set DATABASE_URL postgres://localhost:5432/myapp

# Add to .gitignore (vault init does this automatically)
echo ".vault/" >> .gitignore
```

### Step 2: Share the key with your team

```bash
# Option A: Share via secure channel (1Password, Slack DM, etc.)
cat .vault/key
# Give this to teammates — they put it in their .vault/key

# Option B: Use VAULT_KEY env var
# Each developer sets VAULT_KEY in their shell profile

# Option C: Use the vault server (best for teams > 5)
vault login --api-url https://vault.internal.company.com
```

### Step 3: Add to project README

```markdown
## Development Setup

1. Install vault: `npm install -g @midsummerai/vault`
2. Get the vault key from [1Password/your-secure-channel]
3. Create `.vault/key` with the key, or set `VAULT_KEY` env var
4. Run the dev server: `vault run -- npm run dev`
```

### Step 4: Install the Claude Code plugin

```bash
# Prevents AI agents from reading .env files or inspecting env vars
claude plugin install midsummer-vault
```
