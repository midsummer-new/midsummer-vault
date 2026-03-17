---
description: "Check vault status and list available secret names"
allowed-tools: "Bash"
---

Check if vault is configured and list available secret names (values are never shown):

```bash
# Check if vault CLI is installed
which vault || echo "vault CLI not installed — run: npm install -g @midsummerai/vault"

# Check if .vault.toml exists
if [ -f .vault.toml ]; then
  echo "Vault config found:"
  cat .vault.toml
  echo ""
  vault list 2>&1 || echo "Not authenticated — run: vault login"
else
  echo "No .vault.toml found — run /vault-setup to configure vault for this project"
fi
```
