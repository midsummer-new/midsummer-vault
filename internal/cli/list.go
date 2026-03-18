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
	Long: `Lists all secret names (not values) from the local vault.
Use --global to list global secrets, --all for both local and global.
With --remote, lists from the remote server instead.
With --verbose / -v, shows descriptions and rotation status.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		remote, _ := cmd.Flags().GetBool("remote")
		global, _ := cmd.Flags().GetBool("global")
		all, _ := cmd.Flags().GetBool("all")
		env, _ := cmd.Flags().GetString("env")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if remote {
			return listRemote()
		}
		if all {
			return listAll(env, verbose)
		}
		if global {
			return listGlobal(env, verbose)
		}
		return listLocal(env, verbose)
	},
}

func init() {
	listCmd.Flags().Bool("remote", false, "List secrets from remote server instead of local vault")
	listCmd.Flags().Bool("global", false, "List secrets from global vault (~/.vault/)")
	listCmd.Flags().Bool("all", false, "List secrets from both local and global vaults")
	listCmd.Flags().String("env", store.DefaultEnv, "Target environment (development, staging, production)")
	listCmd.Flags().BoolP("verbose", "v", false, "Show descriptions and rotation status")
}

// formatSecretLine returns a name with optional description and rotation badge.
func formatSecretLine(name string, meta *store.SecretMeta) string {
	line := name

	if meta == nil {
		return line
	}

	// description
	desc := meta.Description
	if desc == "" {
		desc = "(no description)"
	}
	line += fmt.Sprintf("  %s%s%s", dim, desc, reset)

	// rotation badge
	status, days := meta.RotationInfo()
	switch status {
	case store.RotationOK:
		// no badge needed
	case store.RotationDueSoon:
		line += fmt.Sprintf("  %s⚠ rotation due in %d days%s", yellow, days, reset)
	case store.RotationOverdue:
		line += fmt.Sprintf("  %s⚠ rotation overdue by %d days%s", yellow, -days, reset)
	}

	return line
}

func listLocal(env string, verbose bool) error {
	s, err := store.OpenWithEnv(env)
	if err != nil {
		return err
	}

	names, err := s.List()
	if err != nil {
		return err
	}

	if len(names) == 0 {
		fmt.Fprintf(os.Stderr, "No secrets found (%s). Run `vault set KEY value` to add one.\n", env)
		return nil
	}

	var meta store.MetaStore
	if verbose {
		meta, _ = s.LoadMeta()
	}

	sort.Strings(names)
	for _, name := range names {
		if verbose {
			fmt.Printf("  %s\n", formatSecretLine(name, meta[name]))
		} else {
			fmt.Println(name)
		}
	}
	return nil
}

func listGlobal(env string, verbose bool) error {
	s, err := store.OpenGlobalWithEnv(env)
	if err != nil {
		return err
	}

	names, err := s.List()
	if err != nil {
		return err
	}

	if len(names) == 0 {
		fmt.Fprintf(os.Stderr, "No global secrets found (%s). Run `vault set --global KEY value` to add one.\n", env)
		return nil
	}

	var meta store.MetaStore
	if verbose {
		meta, _ = s.LoadMeta()
	}

	sort.Strings(names)
	for _, name := range names {
		if verbose {
			fmt.Printf("  %s\n", formatSecretLine(name, meta[name]))
		} else {
			fmt.Println(name)
		}
	}
	return nil
}

func listAll(env string, verbose bool) error {
	hasLocal := store.Exists()
	hasGlobal := store.GlobalExists()

	if !hasLocal && !hasGlobal {
		fmt.Fprintln(os.Stderr, "No vaults found. Run `vault init` or `vault init --global`.")
		return nil
	}

	// collect local names + meta
	var localNames []string
	var localMeta store.MetaStore
	if hasLocal {
		s, err := store.OpenWithEnv(env)
		if err == nil {
			localNames, _ = s.List()
			if verbose {
				localMeta, _ = s.LoadMeta()
			}
		}
	}

	// collect global names + meta
	var globalNames []string
	var globalMeta store.MetaStore
	if hasGlobal {
		s, err := store.OpenGlobalWithEnv(env)
		if err == nil {
			globalNames, _ = s.List()
			if verbose {
				globalMeta, _ = s.LoadMeta()
			}
		}
	}

	// build a set of local names for quick lookup
	localSet := make(map[string]bool, len(localNames))
	for _, n := range localNames {
		localSet[n] = true
	}

	sort.Strings(localNames)
	sort.Strings(globalNames)

	if len(localNames) > 0 {
		fmt.Printf("%s[local — %s]%s\n", bold, env, reset)
		for _, name := range localNames {
			if verbose {
				fmt.Printf("  %s\n", formatSecretLine(name, localMeta[name]))
			} else {
				fmt.Printf("  %s\n", name)
			}
		}
	}

	if len(globalNames) > 0 {
		if len(localNames) > 0 {
			fmt.Println()
		}
		fmt.Printf("%s[global — %s]%s\n", bold, env, reset)
		for _, name := range globalNames {
			override := ""
			if localSet[name] {
				override = fmt.Sprintf("  %s(overridden by local)%s", dim, reset)
			}
			if verbose {
				fmt.Printf("  %s%s\n", formatSecretLine(name, globalMeta[name]), override)
			} else {
				fmt.Printf("  %s%s\n", name, override)
			}
		}
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
