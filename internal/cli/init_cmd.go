package cli

import (
	"fmt"

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

For CI/CD, set the VAULT_KEY env var instead of using the key file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		hexKey, err := store.Init()
		if err != nil {
			return err
		}

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
