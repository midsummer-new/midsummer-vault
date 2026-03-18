package cli

import (
	"fmt"
	"strings"

	"github.com/midsummer-new/midsummer-vault/internal/store"
	"github.com/spf13/cobra"
)

var describeCmd = &cobra.Command{
	Use:   "describe KEY [DESCRIPTION]",
	Short: "Document a secret with a markdown file",
	Long: `Creates or updates .vault/docs/KEY.md with documentation for a secret.
These markdown files can be committed to git and rendered as documentation pages.

If DESCRIPTION is provided, generates a doc from it.
If omitted, creates a template you can edit.

Examples:
  vault describe STRIPE_KEY "Stripe live key for payments"
  vault describe DATABASE_URL
  vault describe --global OPENAI_KEY "Shared OpenAI key for all projects"`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		if name == "" {
			return fmt.Errorf("secret name cannot be empty")
		}

		description := ""
		if len(args) >= 2 {
			description = strings.Join(args[1:], " ")
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

		// update meta.json description too
		s.SetMeta(name, func(m *store.SecretMeta) {
			if description != "" {
				m.Description = description
			}
			if m.CreatedAt == "" {
				m.CreatedAt = store.NowISO()
			}
		})

		// write .vault/docs/KEY.md
		existing := s.ReadDoc(name)
		if existing != "" && description == "" {
			fmt.Printf("  docs already exist: .vault/docs/%s.md\n", name)
			return nil
		}

		doc := store.GenerateDocTemplate(name, description)
		if err := s.WriteDoc(name, doc); err != nil {
			return fmt.Errorf("write doc: %w", err)
		}

		fmt.Printf("✓ Documented %s → .vault/docs/%s.md\n", name, name)
		return nil
	},
}

func init() {
	describeCmd.Flags().Bool("global", false, "Target global vault (~/.vault/)")
	describeCmd.Flags().String("env", store.DefaultEnv, "Target environment")
}
