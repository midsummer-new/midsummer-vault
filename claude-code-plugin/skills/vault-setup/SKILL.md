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
- Project needs headless/CI secret injection

## Quick Setup

### 1. Install the CLI

```bash
npm install -g @midsummerai/vault
```

### 2. Start a Vault Server (or use Midsummer Cloud)

**Self-hosted (Docker):**
```bash
export VAULT_ENCRYPTION_KEY=$(openssl rand -hex 32)
export SESSION_SECRET=$(openssl rand -base64 48)
docker run -d -p 8080:8080 -v vault-data:/data \
  -e VAULT_ENCRYPTION_KEY=$VAULT_ENCRYPTION_KEY \
  -e SESSION_SECRET=$SESSION_SECRET \
  ghcr.io/midsummer-new/vault-server:latest
```

**Then open http://localhost:8080/setup to create your admin account.**

### 3. Authenticate the CLI

```bash
vault login --api-url http://localhost:8080
```

### 4. Create a Project and Set Secrets

```bash
# Create project via API
curl -X POST http://localhost:8080/api/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-project"}'
# Returns: {"id": "proj_xxx", "name": "my-project"}

# Add .vault.toml to your project root
cat > .vault.toml << 'EOF'
[vault]
project_id = "proj_xxx"
api_url = "http://localhost:8080"
EOF

# Set secrets via API
curl -X POST http://localhost:8080/api/vault/proj_xxx/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "STRIPE_KEY", "value": "sk_live_..."}'
```

### 5. Run Commands with Secrets

```bash
# secrets are injected as env vars — agent never sees them
vault run -- npm run dev
vault run -- python manage.py runserver
```

## How It Protects Against Agents

1. **`vault run`** fetches secrets server-side, injects them into the child process via `syscall.Exec` — the agent process never has access to the values
2. **Shell hardening** blocks `env`, `printenv`, `export -p`, `declare -x`, `compgen -v` inside sandboxes
3. **Output redaction** strips secret values from captured output before the agent sees them
4. **This plugin's hooks** block Bash commands that try to read .env files or echo secrets

## For CI/CD and Sandboxes

```bash
# Get a service token (4h, project-scoped)
export VAULT_SERVICE_TOKEN=<token from API>
export VAULT_PROJECT_ID=proj_xxx
export VAULT_API_URL=http://your-vault:8080

vault run -- npm test
```

## CLAUDE.md Snippet

Add this to your project's CLAUDE.md to enforce vault usage:

```markdown
## Secrets Management

NEVER hardcode API keys, tokens, or passwords in source code or .env files.
All secrets are managed via Midsummer Vault.

- Use `vault run -- <command>` to run commands that need secrets
- Never read, cat, or echo .env files containing real secrets
- Use .env.example with placeholder values for documentation
- For CI/CD: use VAULT_SERVICE_TOKEN (4h, project-scoped, non-refreshable)
```
