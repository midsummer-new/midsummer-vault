package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/Reichel1/midsummer/vault-cli/internal/store"
	"github.com/spf13/cobra"
)

var setCmd = &cobra.Command{
	Use:   "set KEY value",
	Short: "Set a secret in the local vault",
	Long: `Encrypts and stores a secret locally in .vault/secrets.enc.
Use --global to store in ~/.vault/ instead.
Value can also be piped via stdin.

Flags:
  --desc     Attach a human-readable description
  --rotate   Set rotation interval in days (tracks last_rotated_at)`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		if name == "" {
			return fmt.Errorf("secret name cannot be empty")
		}

		var value string
		if len(args) >= 2 {
			value = strings.Join(args[1:], " ")
		} else {
			return fmt.Errorf("usage: vault set KEY value")
		}

		global, _ := cmd.Flags().GetBool("global")
		env, _ := cmd.Flags().GetString("env")
		desc, _ := cmd.Flags().GetString("desc")
		rotateDays, _ := cmd.Flags().GetInt("rotate")

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

		if err := s.Set(name, value); err != nil {
			return fmt.Errorf("failed to set secret: %w", err)
		}

		// persist metadata if --desc or --rotate provided
		if desc != "" || rotateDays > 0 {
			if err := s.SetMeta(name, func(m *store.SecretMeta) {
				if m.CreatedAt == "" {
					m.CreatedAt = store.NowISO()
				}
				if desc != "" {
					m.Description = desc
				}
				if rotateDays > 0 {
					m.RotateEveryDays = rotateDays
					m.LastRotatedAt = store.NowISO()
				}
			}); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ failed to save metadata: %v\n", err)
			}
		}

		// auto-create doc if --desc provided and no doc exists yet
		if desc != "" && s.ReadDoc(name) == "" {
			s.WriteDoc(name, store.GenerateDocTemplate(name, desc))
		}

		scope := "local"
		if global {
			scope = "global"
		}
		fmt.Printf("✓ Set %s (%s, %s)\n", name, scope, env)

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
	setCmd.Flags().Bool("global", false, "Store in global vault (~/.vault/) instead of project vault")
	setCmd.Flags().String("env", store.DefaultEnv, "Target environment (development, staging, production)")
	setCmd.Flags().String("desc", "", "Description of what this secret is for")
	setCmd.Flags().Int("rotate", 0, "Rotation interval in days (e.g. 90)")
}
