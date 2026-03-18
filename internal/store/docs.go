package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DocsDir returns the path to .vault/docs/
func (s *Store) DocsDir() string {
	return filepath.Join(s.dir, "docs")
}

// DocPath returns the path to .vault/docs/KEY.md
func (s *Store) DocPath(name string) string {
	return filepath.Join(s.DocsDir(), name+".md")
}

// WriteDoc creates or overwrites .vault/docs/KEY.md
func (s *Store) WriteDoc(name, content string) error {
	dir := s.DocsDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create docs dir: %w", err)
	}
	return os.WriteFile(s.DocPath(name), []byte(content), 0644)
}

// ReadDoc reads .vault/docs/KEY.md, returns empty string if not found.
func (s *Store) ReadDoc(name string) string {
	data, err := os.ReadFile(s.DocPath(name))
	if err != nil {
		return ""
	}
	return string(data)
}

// DeleteDoc removes .vault/docs/KEY.md
func (s *Store) DeleteDoc(name string) {
	os.Remove(s.DocPath(name))
}

// RenameDoc moves OLD.md to NEW.md
func (s *Store) RenameDoc(oldName, newName string) {
	old := s.DocPath(oldName)
	if _, err := os.Stat(old); err == nil {
		os.Rename(old, s.DocPath(newName))
	}
}

// ListDocs returns all documented secret names (from .vault/docs/*.md)
func (s *Store) ListDocs() []string {
	entries, err := os.ReadDir(s.DocsDir())
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			names = append(names, strings.TrimSuffix(e.Name(), ".md"))
		}
	}
	return names
}

// GenerateDocTemplate creates a starter markdown doc for a secret.
func GenerateDocTemplate(name, description string) string {
	doc := "# " + name + "\n\n"
	if description != "" {
		doc += description + "\n\n"
	} else {
		doc += "*(no description yet)*\n\n"
	}
	doc += "## Usage\n\n"
	doc += "Available as `" + name + "` environment variable via `vault run`.\n\n"
	doc += "## Where to find\n\n"
	doc += "*(add provider URL or instructions)*\n\n"
	doc += "## Notes\n\n"
	doc += "*(add any relevant notes)*\n"
	return doc
}
