package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// local project registry stored in ~/.config/midsummerai/vault/projects.json
type projectEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

var projectCmd = &cobra.Command{
	Use:   "project",
	Short: "Manage vault projects",
	Long:  "Create, list, and switch between vault projects locally.",
}

var projectCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new vault project and initialize it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		if name == "" {
			return fmt.Errorf("project name cannot be empty")
		}

		// generate project ID
		id := uuid.New().String()

		// get current directory
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}

		// write .vault.toml
		toml := fmt.Sprintf("[vault]\nproject_id = %q\nproject_name = %q\n", id, name)
		if err := os.WriteFile(".vault.toml", []byte(toml), 0644); err != nil {
			return fmt.Errorf("write .vault.toml: %w", err)
		}

		// register in local project list
		if err := addProject(projectEntry{ID: id, Name: name, Path: cwd}); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ failed to register project: %v\n", err)
		}

		// init vault if not already done
		if _, err := os.Stat(".vault"); os.IsNotExist(err) {
			cmd.Root().SetArgs([]string{"init"})
			cmd.Root().Execute()
		}

		fmt.Printf("✓ Created project %q\n", name)
		fmt.Printf("  id: %s\n", id)
		fmt.Printf("  → .vault.toml written\n")
		return nil
	},
}

var projectListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your vault projects",
	RunE: func(cmd *cobra.Command, args []string) error {
		projects, err := loadProjects()
		if err != nil || len(projects) == 0 {
			fmt.Println("No projects yet. Create one with: vault project create \"My App\"")
			return nil
		}

		// check current project
		currentID := ""
		if data, err := os.ReadFile(".vault.toml"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "project_id") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						currentID = strings.Trim(strings.TrimSpace(parts[1]), "\"")
					}
				}
			}
		}

		for _, p := range projects {
			marker := "  "
			if p.ID == currentID {
				marker = "→ "
			}
			fmt.Printf("%s%s  %s%s%s\n", marker, p.Name, dim, p.Path, reset)
		}
		return nil
	},
}

var projectUseCmd = &cobra.Command{
	Use:   "use [name-or-id]",
	Short: "Link current directory to an existing project",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		idOrName := strings.TrimSpace(args[0])

		projects, err := loadProjects()
		if err != nil || len(projects) == 0 {
			return fmt.Errorf("no projects found — run `vault project create \"My App\"` first")
		}

		var match *projectEntry
		for i, p := range projects {
			if p.ID == idOrName || strings.EqualFold(p.Name, idOrName) {
				match = &projects[i]
				break
			}
		}
		if match == nil {
			return fmt.Errorf("project %q not found — run `vault project list`", idOrName)
		}

		toml := fmt.Sprintf("[vault]\nproject_id = %q\nproject_name = %q\n", match.ID, match.Name)
		if err := os.WriteFile(".vault.toml", []byte(toml), 0644); err != nil {
			return fmt.Errorf("write .vault.toml: %w", err)
		}

		fmt.Printf("✓ Linked to %q\n", match.Name)
		return nil
	},
}

var projectRenameCmd = &cobra.Command{
	Use:   "rename [new-name]",
	Short: "Rename the current project",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		newName := strings.TrimSpace(args[0])
		if newName == "" {
			return fmt.Errorf("name cannot be empty")
		}

		// read current project ID from .vault.toml
		data, err := os.ReadFile(".vault.toml")
		if err != nil {
			return fmt.Errorf("no .vault.toml — run `vault project create` first")
		}

		var currentID string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "project_id") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					currentID = strings.Trim(strings.TrimSpace(parts[1]), "\"")
				}
			}
		}
		if currentID == "" {
			return fmt.Errorf("no project_id in .vault.toml")
		}

		// update .vault.toml
		toml := fmt.Sprintf("[vault]\nproject_id = %q\nproject_name = %q\n", currentID, newName)
		if err := os.WriteFile(".vault.toml", []byte(toml), 0644); err != nil {
			return fmt.Errorf("write .vault.toml: %w", err)
		}

		// update registry
		projects, _ := loadProjects()
		for i, p := range projects {
			if p.ID == currentID {
				projects[i].Name = newName
				saveProjects(projects)
				break
			}
		}

		fmt.Printf("✓ Renamed project to %q\n", newName)
		return nil
	},
}

var projectDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete the current project's vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		confirm, _ := cmd.Flags().GetBool("yes")

		if _, err := os.Stat(".vault"); os.IsNotExist(err) {
			return fmt.Errorf("no vault in this directory")
		}

		if !confirm {
			return fmt.Errorf("add --yes to confirm deletion of .vault/ and all secrets")
		}

		// read project ID before deleting
		var currentID string
		if data, err := os.ReadFile(".vault.toml"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "project_id") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						currentID = strings.Trim(strings.TrimSpace(parts[1]), "\"")
					}
				}
			}
		}

		os.RemoveAll(".vault")
		os.Remove(".vault.toml")
		os.Remove(".env.local")

		// remove from registry
		if currentID != "" {
			projects, _ := loadProjects()
			var filtered []projectEntry
			for _, p := range projects {
				if p.ID != currentID {
					filtered = append(filtered, p)
				}
			}
			saveProjects(filtered)
		}

		fmt.Println("✓ Vault deleted")
		return nil
	},
}

func init() {
	projectCmd.AddCommand(projectCreateCmd)
	projectCmd.AddCommand(projectListCmd)
	projectCmd.AddCommand(projectUseCmd)
	projectCmd.AddCommand(projectRenameCmd)
	projectCmd.AddCommand(projectDeleteCmd)
	projectDeleteCmd.Flags().Bool("yes", false, "Confirm deletion")
}

// --- local project registry ---

func projectsFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "midsummerai", "vault", "projects.json")
}

func loadProjects() ([]projectEntry, error) {
	data, err := os.ReadFile(projectsFilePath())
	if err != nil {
		return nil, nil
	}
	var projects []projectEntry
	json.Unmarshal(data, &projects)
	return projects, nil
}

func addProject(p projectEntry) error {
	projects, _ := loadProjects()

	// deduplicate by ID
	for i, existing := range projects {
		if existing.ID == p.ID {
			projects[i] = p
			return saveProjects(projects)
		}
	}

	projects = append(projects, p)
	return saveProjects(projects)
}

func saveProjects(projects []projectEntry) error {
	path := projectsFilePath()
	os.MkdirAll(filepath.Dir(path), 0700)
	data, _ := json.MarshalIndent(projects, "", "  ")
	return os.WriteFile(path, data, 0600)
}
