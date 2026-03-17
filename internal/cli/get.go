package cli

import (
	"fmt"
	"strings"

	"github.com/Reichel1/midsummer/vault-cli/internal/store"
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get KEY",
	Short: "Get a secret value from the local vault",
	Long:  "Decrypts and prints a single secret. Use `vault run` instead to inject all secrets into a process.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])

		s, err := store.Open()
		if err != nil {
			return err
		}

		value, err := s.Get(name)
		if err != nil {
			return err
		}

		fmt.Print(value)
		return nil
	},
}
