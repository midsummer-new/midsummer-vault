package cli

import (
	"fmt"
	"strings"

	"github.com/Reichel1/midsummer/vault-cli/internal/store"
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get KEY",
	Short: "Get a secret value from the vault",
	Long:  "Decrypts and prints a single secret. Checks local vault first, then global.\nUse `vault run` instead to inject all secrets into a process.\nUse --env to target a specific environment (default: development).",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		env, _ := cmd.Flags().GetString("env")

		// try local vault first
		if store.Exists() {
			s, err := store.OpenWithEnv(env)
			if err == nil {
				value, err := s.Get(name)
				if err == nil {
					fmt.Print(value)
					return nil
				}
			}
		}

		// fall through to global vault
		if store.GlobalExists() {
			s, err := store.OpenGlobalWithEnv(env)
			if err == nil {
				value, err := s.Get(name)
				if err == nil {
					fmt.Print(value)
					return nil
				}
			}
		}

		return fmt.Errorf("secret %q not found in local or global vault (%s)", name, env)
	},
}

func init() {
	getCmd.Flags().String("env", store.DefaultEnv, "Target environment (development, staging, production)")
}
