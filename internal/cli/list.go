package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/Reichel1/midsummer/vault-cli/internal/store"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List secret names in the vault",
	Long:  "Lists all secret names (not values) from the local vault.\nWith --remote, lists from the remote server instead.",
	RunE: func(cmd *cobra.Command, args []string) error {
		remote, _ := cmd.Flags().GetBool("remote")

		if remote {
			return listRemote()
		}
		return listLocal()
	},
}

func init() {
	listCmd.Flags().Bool("remote", false, "List secrets from remote server instead of local vault")
}

func listLocal() error {
	s, err := store.Open()
	if err != nil {
		return err
	}

	names, err := s.List()
	if err != nil {
		return err
	}

	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "No secrets found. Run `vault set KEY value` to add one.")
		return nil
	}

	sort.Strings(names)
	for _, name := range names {
		fmt.Println(name)
	}
	return nil
}

func listRemote() error {
	cr, err := getClientAndProject()
	if err != nil {
		return err
	}

	names, err := cr.client.GetSecretNames(cr.projectID)
	if err != nil {
		return fmt.Errorf("failed to fetch secrets: %w", err)
	}

	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "No secrets found on remote.")
		return nil
	}

	for _, name := range names {
		fmt.Println(name)
	}
	return nil
}
