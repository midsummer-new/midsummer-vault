package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Reichel1/midsummer/vault-cli/internal/store"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a local vault in the current directory",
	Long: `Creates a .vault/ directory with an encrypted secrets store.

Generates a random 256-bit encryption key stored in .vault/key.
Secrets are encrypted with AES-256-GCM and stored in .vault/secrets.enc.
The .vault/ directory is automatically git-ignored.

Also sets up .claude/rules/vault.md so AI agents know how to use the vault.

Use --global to create a global vault at ~/.vault/ for secrets shared
across all projects (e.g., OPENAI_API_KEY).

For CI/CD, set the VAULT_KEY env var instead of using the key file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		global, _ := cmd.Flags().GetBool("global")
		passphrase, _ := cmd.Flags().GetString("passphrase")

		// passphrase mode — no key file, derive from password
		if passphrase != "" {
			if len(passphrase) < 8 {
				return fmt.Errorf("passphrase must be at least 8 characters")
			}
			var err error
			if global {
				err = store.InitGlobalWithPassphrase(passphrase)
			} else {
				err = store.InitWithPassphrase(passphrase)
			}
			if err != nil {
				return err
			}

			loc := ".vault/"
			if global {
				loc = "~/.vault/"
			}
			fmt.Printf("✓ Vault initialized in %s (passphrase-protected)\n", loc)
			fmt.Println("")
			fmt.Println("  No key file created — your passphrase IS the key.")
			fmt.Println("  Set VAULT_PASSPHRASE env var for CI/CD.")
			fmt.Println("")
			fmt.Println("  Next steps:")
			fmt.Println("    vault set STRIPE_KEY sk_live_...")
			fmt.Println("    vault run -- npm run dev")

			if !global {
				setupClaudeRules()
				addToGitignore()
			}
			return nil
		}

		if global {
			hexKey, err := store.InitGlobal()
			if err != nil {
				return err
			}

			fmt.Println("✓ Global vault initialized in ~/.vault/")
			fmt.Println("")
			fmt.Println("  Your encryption key (save this somewhere safe):")
			fmt.Printf("  VAULT_KEY=%s\n", hexKey)
			fmt.Println("")
			fmt.Println("  Next steps:")
			fmt.Println("    vault set --global OPENAI_API_KEY sk-...")
			fmt.Println("    vault set --global REDIS_URL redis://...")
			fmt.Println("    vault list --global")
			return nil
		}

		hexKey, err := store.Init()
		if err != nil {
			return err
		}

		// set up .claude/rules so AI agents know about vault
		setupClaudeRules()

		// add .vault/ to .gitignore if it exists
		addToGitignore()

		fmt.Println("✓ Vault initialized in .vault/")
		fmt.Println("")
		fmt.Println("  Your encryption key (save this for CI/CD):")
		fmt.Printf("  VAULT_KEY=%s\n", hexKey)
		fmt.Println("")
		fmt.Println("  Next steps:")
		fmt.Println("    vault set STRIPE_KEY sk_live_...")
		fmt.Println("    vault set DATABASE_URL postgres://...")
		fmt.Println("    vault run -- npm run dev")
		return nil
	},
}

func init() {
	initCmd.Flags().Bool("global", false, "Initialize global vault at ~/.vault/ for shared secrets")
	initCmd.Flags().String("passphrase", "", "Use a passphrase instead of a key file (no key to lose)")
}

const vaultRule = `# Midsummer Vault

Secrets managed through Midsummer Vault (NOT HashiCorp Vault). Be brief — just use it.
Load the midsummer-vault skill for full command reference.

## Auto-setup (do silently)

` + "```bash" + `
which vault && vault --version 2>&1 | grep -q midsummer || npm install -g @midsummerai/vault
[ -d .vault ] || vault project create "$(basename $(pwd))"
` + "```" + `

## Secrets

If [vault:SECRET_xxx] in prompt — hook stored it:
` + "`vault rename SECRET_xxx DERIVED_NAME`" + ` then ` + "`vault describe DERIVED_NAME \"desc\"`" + `

If raw value: ` + "`vault set KEY \"value\" --desc \"desc\"`" + `

Say only: "Stored as KEY."

## Environments

Three envs: ` + "`--env development`" + ` (default), ` + "`--env staging`" + `, ` + "`--env production`" + `

` + "`vault set KEY val --env staging --desc \"desc\"`" + ` — store in staging
` + "`vault run --env staging -- cmd`" + ` — run with staging secrets
` + "`vault copy KEY --from development --to production`" + ` — copy between envs (value never exposed)
` + "`vault list --env production`" + ` — list production secrets

## Commands: always ` + "`vault run --env ENV -- <command>`" + `

## Rules

- "Stored as KEY." Nothing more.
- Auto-setup silently
- NEVER run ` + "`vault get`" + `
- NEVER store ` + "`[vault:...]`" + ` references as values — use ` + "`vault copy`" + ` to move between envs
- NEVER hardcode secrets
- NEVER write .env manually — use ` + "`vault env`" + `
- NEVER output command examples unless asked
- NEVER explain vault unless asked
`

func setupClaudeRules() {
	rulesDir := filepath.Join(".claude", "rules")
	rulePath := filepath.Join(rulesDir, "vault.md")

	// don't overwrite if already exists
	if _, err := os.Stat(rulePath); err == nil {
		return
	}

	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		return // silently skip if we can't create
	}

	os.WriteFile(rulePath, []byte(vaultRule), 0644)
	fmt.Println("✓ Added .claude/rules/vault.md")

	// also create skill
	skillDir := filepath.Join(".claude", "skills", "midsummer-vault")
	skillPath := filepath.Join(skillDir, "SKILL.md")
	if _, err := os.Stat(skillPath); err != nil {
		os.MkdirAll(skillDir, 0755)
		os.WriteFile(skillPath, []byte(vaultSkill), 0644)
		fmt.Println("✓ Added .claude/skills/midsummer-vault/SKILL.md")
	}
}

const vaultSkill = `---
name: midsummer-vault
description: This skill should be used when "[vault:SECRET_" appears in the conversation (indicating the hook redacted a secret), when any secret, API key, token, credential, password, or environment variable is mentioned, when "vault" is mentioned, or when running commands that need secrets. Activates on vault references, secret storage, and credential management. This is Midsummer Vault — NOT HashiCorp Vault.
---

# Midsummer Vault

Midsummer Vault encrypts secrets locally and injects them into child processes at runtime. The AI agent never sees actual secret values. Install: ` + "`npm install -g @midsummerai/vault`" + `

## Setup (run silently before any vault operation)

` + "```bash" + `
which vault && vault --version 2>&1 | grep -q midsummer || npm install -g @midsummerai/vault
[ -d .vault ] || vault project create "$(basename $(pwd))"
` + "```" + `

## Handling Secrets from User Messages

When the hook intercepts a secret, the prompt contains ` + "`[vault:SECRET_xxxxxxxx]`" + ` references. The hook already stored the real value.

1. Derive env var name from context
2. Run ` + "`vault rename SECRET_xxxxxxxx DERIVED_NAME`" + `
3. Run ` + "`vault describe DERIVED_NAME \"description\"`" + `
4. Respond only: "Stored as DERIVED_NAME."

When raw value visible (hook missed):
1. Run ` + "`vault set KEY \"value\" --desc \"description\"`" + `
2. Respond only: "Stored as KEY."

## Environments

` + "`--env development`" + ` (default), ` + "`--env staging`" + `, ` + "`--env production`" + `

## Running Commands: always ` + "`vault run -- <command>`" + `

## Commands

| Command | Purpose |
|---------|---------|
| ` + "`vault project create \"name\"`" + ` | Create and initialize |
| ` + "`vault project list`" + ` | List projects |
| ` + "`vault project rename \"name\"`" + ` | Rename current |
| ` + "`vault set KEY val --desc \"...\" --env ENV`" + ` | Store secret |
| ` + "`vault set --global KEY val`" + ` | Store shared |
| ` + "`vault rm KEY`" + ` | Remove |
| ` + "`vault rename OLD NEW`" + ` | Rename (NO --desc flag) |
| ` + "`vault describe KEY \"desc\"`" + ` | Add description |
| ` + "`vault list`" + ` / ` + "`-v`" + ` / ` + "`--all`" + ` | List secrets |
| ` + "`vault run --env ENV -- cmd`" + ` | Run with secrets |
| ` + "`vault env`" + ` | Generate .env.local |
| ` + "`vault import .env`" + ` | Bulk import |
| ` + "`vault status`" + ` | Show state |

## Rules

- Respond "Stored as KEY." — nothing more
- Auto-setup vault silently without asking
- NEVER run ` + "`vault get`" + ` (blocked — user runs it)
- NEVER write .env files manually — use ` + "`vault env`" + `
- NEVER hardcode secrets in code
- NEVER output command examples unless asked
- NEVER explain vault unless asked
`

func addToGitignore() {
	gi := ".gitignore"
	vaultIgnore := "\n# vault — ignore secrets, allow docs\n.vault/*\n!.vault/docs/\n!.vault/.gitignore\n.env.local\n"

	content, err := os.ReadFile(gi)
	if err != nil {
		os.WriteFile(gi, []byte(vaultIgnore[1:]), 0644) // trim leading \n
		return
	}

	if contains(string(content), ".vault") {
		return
	}

	f, err := os.OpenFile(gi, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(vaultIgnore)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsLine(s, substr))
}

func containsLine(s, substr string) bool {
	for _, line := range splitLines(s) {
		if line == substr || line == substr+"/" {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
