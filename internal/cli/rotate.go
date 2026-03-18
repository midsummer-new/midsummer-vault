package cli

import (
	"fmt"
	"strings"

	"github.com/midsummer-new/midsummer-vault/internal/store"
	"github.com/spf13/cobra"
)

var rotateCmd = &cobra.Command{
	Use:   "rotate KEY",
	Short: "Mark a secret as rotated (updates last_rotated_at to now)",
	Long: `Records that you have rotated a secret at the provider.
This does NOT change the secret value — you're expected to have already
rotated the actual key at the provider and updated it with "vault set".

Example:
  vault rotate STRIPE_KEY`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		if name == "" {
			return fmt.Errorf("secret name cannot be empty")
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

		// verify the secret exists
		names, err := s.List()
		if err != nil {
			return err
		}
		found := false
		for _, n := range names {
			if n == name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("secret %q not found", name)
		}

		if err := s.SetMeta(name, func(m *store.SecretMeta) {
			m.LastRotatedAt = store.NowISO()
		}); err != nil {
			return fmt.Errorf("failed to update rotation timestamp: %w", err)
		}

		fmt.Printf("✓ Marked %s as rotated\n", name)
		return nil
	},
}

func init() {
	rotateCmd.Flags().Bool("global", false, "Target global vault (~/.vault/)")
	rotateCmd.Flags().String("env", store.DefaultEnv, "Target environment (development, staging, production)")
}
