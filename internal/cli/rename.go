package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/midsummer-new/midsummer-vault/internal/store"
	"github.com/spf13/cobra"
)

var renameCmd = &cobra.Command{
	Use:   "rename OLD_NAME NEW_NAME",
	Short: "Rename a secret (maps it to an env var name)",
	Long: `Renames a secret in the local vault. This is how you map auto-detected
secrets to proper environment variable names. Use --global for ~/.vault/.

Example:
  vault rename SECRET_42f19ae1 REDIS_URL
  vault rename --global OLD_KEY NEW_KEY

After renaming, "vault run" injects the secret using the NEW name
as the environment variable.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		oldName := strings.TrimSpace(args[0])
		newName := strings.TrimSpace(args[1])

		if oldName == "" || newName == "" {
			return fmt.Errorf("both old and new names are required")
		}

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

		if err := s.Rename(oldName, newName); err != nil {
			return err
		}

		// move metadata + docs
		_ = s.RenameMeta(oldName, newName)
		s.RenameDoc(oldName, newName)

		fmt.Printf("✓ Renamed %s → %s\n", oldName, newName)
		fmt.Printf("  vault run will inject as: %s=<value>\n", newName)

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
	renameCmd.Flags().Bool("global", false, "Rename in global vault (~/.vault/) instead of project vault")
	renameCmd.Flags().String("env", store.DefaultEnv, "Target environment (development, staging, production)")
}
