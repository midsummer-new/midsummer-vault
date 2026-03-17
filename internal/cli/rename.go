package cli

import (
	"fmt"
	"strings"

	"github.com/Reichel1/midsummer/vault-cli/internal/store"
	"github.com/spf13/cobra"
)

var renameCmd = &cobra.Command{
	Use:   "rename OLD_NAME NEW_NAME",
	Short: "Rename a secret (maps it to an env var name)",
	Long: `Renames a secret in the local vault. This is how you map auto-detected
secrets to proper environment variable names.

Example:
  vault rename SECRET_42f19ae1 REDIS_URL
  vault rename STRIPE_SECRET_c36b STRIPE_SECRET_KEY

After renaming, "vault run" injects the secret using the NEW name
as the environment variable.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		oldName := strings.TrimSpace(args[0])
		newName := strings.TrimSpace(args[1])

		if oldName == "" || newName == "" {
			return fmt.Errorf("both old and new names are required")
		}

		s, err := store.Open()
		if err != nil {
			return err
		}

		if err := s.Rename(oldName, newName); err != nil {
			return err
		}

		fmt.Printf("✓ Renamed %s → %s\n", oldName, newName)
		fmt.Printf("  vault run will inject as: %s=<value>\n", newName)
		return nil
	},
}
