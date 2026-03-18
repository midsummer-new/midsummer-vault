package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/midsummer-new/midsummer-vault/internal/store"
	"github.com/spf13/cobra"
)

var rmCmd = &cobra.Command{
	Use:   "rm KEY",
	Short: "Remove a secret from the vault",
	Long:  "Removes a secret from the local vault. Use --global to remove from ~/.vault/ instead.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])

		global, _ := cmd.Flags().GetBool("global")
		env, _ := cmd.Flags().GetString("env")

		var s *store.Store
		var err error
		if global {
			s, err = store.OpenGlobalWithEnv(env)
		} else {
			s, err = store.OpenWithEnv(env)
		}
		if err != nil {
			return err
		}

		if err := s.Delete(name); err != nil {
			return err
		}

		// clean up metadata + docs
		_ = s.DeleteMeta(name)
		s.DeleteDoc(name)

		scope := "local"
		if global {
			scope = "global"
		}
		fmt.Printf("✓ Removed %s (%s, %s)\n", name, scope, env)

		// auto-sync if configured
		if cfg := store.LoadSyncConfig(); cfg.Enabled && !global {
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
	rmCmd.Flags().Bool("global", false, "Remove from global vault (~/.vault/) instead of project vault")
	rmCmd.Flags().String("env", store.DefaultEnv, "Target environment (development, staging, production)")
}
