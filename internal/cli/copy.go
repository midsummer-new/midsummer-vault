package cli

import (
	"fmt"
	"strings"

	"github.com/midsummer-new/midsummer-vault/internal/store"
	"github.com/spf13/cobra"
)

var copyCmd = &cobra.Command{
	Use:   "copy KEY",
	Short: "Copy a secret to another environment",
	Long: `Copies a secret from one environment to another without exposing the value.

Examples:
  vault copy STRIPE_KEY --from development --to production
  vault copy WORKOS_CLIENT_ID --to staging`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		fromEnv, _ := cmd.Flags().GetString("from")
		toEnv, _ := cmd.Flags().GetString("to")

		if toEnv == "" {
			return fmt.Errorf("--to is required")
		}

		src, err := store.OpenWithEnv(fromEnv)
		if err != nil {
			return fmt.Errorf("open source env: %w", err)
		}

		value, err := src.Get(name)
		if err != nil {
			return fmt.Errorf("secret %q not found in %s", name, fromEnv)
		}

		dst, err := store.OpenWithEnv(toEnv)
		if err != nil {
			return fmt.Errorf("open target env: %w", err)
		}

		if err := dst.Set(name, value); err != nil {
			return fmt.Errorf("set in %s: %w", toEnv, err)
		}

		fmt.Printf("✓ Copied %s from %s to %s\n", name, fromEnv, toEnv)
		return nil
	},
}

func init() {
	copyCmd.Flags().String("from", store.DefaultEnv, "Source environment")
	copyCmd.Flags().String("to", "", "Target environment (required)")
}
