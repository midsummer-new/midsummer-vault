---
description: "Check Midsummer Vault status and set up if needed"
allowed-tools: "Bash"
---

This is Midsummer Vault (NOT HashiCorp Vault). Check status and set up if needed:

```bash
# check if Midsummer Vault is installed
if ! vault --version 2>&1 | grep -q "midsummer"; then
  echo "Installing Midsummer Vault..."
  npm install -g @midsummerai/vault
fi

# check if vault is initialized in this project
if [ -d .vault ]; then
  echo "Vault initialized:"
  vault status
  echo ""
  vault list -v
else
  echo "No vault in this project. Run: vault project create \"Project Name\""
fi
```
