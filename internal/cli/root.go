package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time via ldflags.
var Version = "dev"

// ansi colors
const (
	bold   = "\033[1m"
	dim    = "\033[2m"
	cyan   = "\033[36m"
	green  = "\033[32m"
	yellow = "\033[33m"
	reset  = "\033[0m"
)

var rootCmd = &cobra.Command{
	Use:   "vault",
	Short: "Secret management for AI agents",
	Long: bold + `vault` + reset + ` — keep API keys away from AI agents

Secrets are encrypted locally and injected into child processes at runtime.
The agent orchestrator never sees the actual values.

` + bold + `Quick start:` + reset + `
  vault init                       Create an encrypted vault
  vault set STRIPE_KEY sk_live_…   Store a secret
  vault run -- npm run dev         Inject secrets into process

` + bold + `Import existing .env:` + reset + `
  vault import .env.local          Bulk import from a dotenv file

` + bold + `Team / CI:` + reset + `
  Share .vault/key with teammates, or set VAULT_KEY env var in CI.
  For shared secrets, use a vault server:
  vault login --api-url https://vault.your-company.com`,
	// override the default help template for grouped commands
	Run: func(cmd *cobra.Command, args []string) {
		printUsage()
	},
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `
%svault%s %s%s%s — secret management for AI agents

%sUsage:%s  vault <command> [flags]

%sSecrets:%s
  init          Create an encrypted vault in the current directory
  set           Store a secret             vault set KEY value
  get           Retrieve a secret          vault get KEY
  rm            Remove a secret            vault rm KEY
  rename        Rename / map to env var    vault rename OLD NEW
  list          List secret names          vault list
  import        Bulk import from .env      vault import .env.local

%sRuntime:%s
  run           Inject secrets and exec    vault run -- npm start

%sRemote:%s %s(optional — for teams)%s
  login         Authenticate to server     vault login --api-url URL
  logout        Clear stored credentials   vault logout
  pull          Download to .env file      vault pull

%sOther:%s
  status        Show vault state           vault status
  help          Help for any command       vault help <command>
  version       Print version              vault --version

%sExamples:%s
  vault init && vault set STRIPE_KEY sk_live_… && vault run -- npm start
  VAULT_KEY=abc… vault run -- node server.js  %s# CI mode, no key file%s
  vault import .env.local                     %s# migrate existing secrets%s
  vault rename SECRET_42f1 REDIS_URL          %s# map auto-detected to env var%s

`, bold, reset, dim, Version, reset,
		bold, reset,
		cyan, reset,
		cyan, reset,
		cyan, reset, dim, reset,
		cyan, reset,
		bold, reset,
		dim, reset,
		dim, reset,
		dim, reset)
}

func init() {
	rootCmd.Version = Version
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SetHelpTemplate(`{{.Long}}
{{if .HasAvailableSubCommands}}
Use "vault <command> --help" for more information about a command.
{{end}}`)

	// secrets
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(setCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(rmCmd)
	rootCmd.AddCommand(renameCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(importCmd)

	// runtime
	rootCmd.AddCommand(runCmd)

	// remote
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(pullCmd)

	// info
	rootCmd.AddCommand(statusCmd)
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
