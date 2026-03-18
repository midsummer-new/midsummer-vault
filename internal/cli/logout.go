package cli

import (
	"fmt"

	"github.com/midsummer-new/midsummer-vault/internal/config"
	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove stored credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.DeleteCredentials(); err != nil {
			return fmt.Errorf("failed to delete credentials: %w", err)
		}
		fmt.Println("✓ Logged out")
		return nil
	},
}
