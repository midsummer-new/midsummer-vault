package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Reichel1/midsummer/vault-cli/internal/config"
	"github.com/Reichel1/midsummer/vault-cli/internal/store"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show vault state and configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("\n%svault status%s\n\n", bold, reset)

		// local vault
		if store.Exists() {
			s, err := store.Open()
			if err != nil {
				fmt.Printf("  %s●%s Local vault  %serror: %v%s\n", yellow, reset, dim, err, reset)
			} else {
				names, _ := s.List()
				keySource := "file (.vault/key)"
				if os.Getenv("VAULT_KEY") != "" {
					keySource = "env (VAULT_KEY)"
				}
				fmt.Printf("  %s●%s Local vault  %s%d secrets%s  key: %s\n",
					green, reset, bold, len(names), reset, keySource)
				if len(names) > 0 {
					for _, n := range names {
						fmt.Printf("    %s•%s %s\n", dim, reset, n)
					}
				}
			}
		} else {
			fmt.Printf("  %s●%s Local vault  %snot initialized%s  → vault init\n", dim, reset, dim, reset)
		}

		fmt.Println()

		// remote server
		projectCfg, _ := config.LoadProjectConfig()
		creds, _ := config.LoadCredentials()

		if projectCfg != nil {
			serverURL := projectCfg.Vault.APIURL
			if serverURL == "" {
				serverURL = defaultAPIURL
			}
			fmt.Printf("  %s●%s Remote server  %s%s%s\n", cyan, reset, dim, serverURL, reset)
			fmt.Printf("    project: %s\n", projectCfg.Vault.ProjectID)

			if creds != nil {
				fmt.Printf("    auth: %s%s%s\n", green, creds.Email, reset)
			} else {
				fmt.Printf("    auth: %snot logged in%s  → vault login\n", yellow, reset)
			}
		} else {
			fmt.Printf("  %s●%s Remote server  %snot configured%s  %s(optional)%s\n",
				dim, reset, dim, reset, dim, reset)
		}

		fmt.Println()

		// env vars
		if os.Getenv("VAULT_SERVICE_TOKEN") != "" {
			fmt.Printf("  %s●%s Service token  %sset%s (headless mode)\n", green, reset, green, reset)
		}
		if os.Getenv("VAULT_KEY") != "" {
			fmt.Printf("  %s●%s VAULT_KEY  %sset%s (CI mode)\n", green, reset, green, reset)
		}

		// gitignore check
		if store.Exists() {
			gi := filepath.Join(".vault", ".gitignore")
			if _, err := os.Stat(gi); err != nil {
				fmt.Printf("\n  %s⚠%s  .vault/.gitignore missing — run vault init\n", yellow, reset)
			}
		}

		fmt.Println()
		return nil
	},
}
