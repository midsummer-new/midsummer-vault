package cli

import (
	"fmt"
	"strings"

	"github.com/Reichel1/midsummer/vault-cli/internal/store"
	"github.com/spf13/cobra"
)

var setCmd = &cobra.Command{
	Use:   "set KEY value",
	Short: "Set a secret in the local vault",
	Long:  "Encrypts and stores a secret locally in .vault/secrets.enc.\nValue can also be piped via stdin.",
	Args:  cobra.MinimumNArgs(1),
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

		s, err := store.Open()
		if err != nil {
			return err
		}

		if err := s.Set(name, value); err != nil {
			return fmt.Errorf("failed to set secret: %w", err)
		}

		fmt.Printf("✓ Set %s\n", name)
		return nil
	},
}
