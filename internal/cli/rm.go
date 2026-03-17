package cli

import (
	"fmt"
	"strings"

	"github.com/Reichel1/midsummer/vault-cli/internal/store"
	"github.com/spf13/cobra"
)

var rmCmd = &cobra.Command{
	Use:   "rm KEY",
	Short: "Remove a secret from the local vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])

		s, err := store.Open()
		if err != nil {
			return err
		}

		if err := s.Delete(name); err != nil {
			return err
		}

		fmt.Printf("✓ Removed %s\n", name)
		return nil
	},
}
