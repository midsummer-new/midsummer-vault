package cli

import (
	"fmt"
	"os"

	"github.com/midsummer-new/midsummer-vault/internal/store"
	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import secrets from a .env file into the local vault",
	Long: `Reads a .env file and stores each KEY=VALUE pair in the local vault.

Lines starting with # and empty lines are skipped.
Surrounding quotes on values are stripped.

Example:
  vault import .env.local
  vault import .env.production`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		env, _ := cmd.Flags().GetString("env")

		entries := readDotEnv(path)
		if len(entries) == 0 {
			return fmt.Errorf("no key=value pairs found in %s (file missing or empty)", path)
		}

		s, err := store.OpenWithEnv(env)
		if err != nil {
			return err
		}

		count := 0
		for k, v := range entries {
			if err := s.Set(k, v); err != nil {
				return fmt.Errorf("failed to set %s: %w", k, err)
			}
			count++
		}

		fmt.Printf("✓ Imported %d secret(s) from %s (%s)\n", count, path, env)

		// auto-sync if configured
		if cfg := store.LoadSyncConfig(); cfg.Enabled {
			if err := store.Push(cfg, env); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ sync failed: %v (using local)\n", err)
			} else {
				fmt.Println("  ↑ synced")
			}
		}

		return nil
	},
}

func init() {
	importCmd.Flags().String("env", store.DefaultEnv, "Target environment (development, staging, production)")
}
