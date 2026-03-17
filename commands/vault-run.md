---
description: "Run a command with vault secrets injected as env vars"
argument-hint: "<command> [args...]"
allowed-tools: "Bash"
---

Run the following command with vault secrets injected. The secrets are fetched from the vault server and injected into the child process environment — they never appear in the agent's context.

```bash
vault run -- $ARGUMENTS
```

If the command fails with "not logged in", run `vault login` first.
If vault is not installed, run `npm install -g @midsummerai/vault`.
