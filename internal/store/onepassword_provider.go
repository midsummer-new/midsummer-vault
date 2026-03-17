package store

import (
	"fmt"
	"sort"
	"strings"
)

// OnePasswordProvider reads secrets from 1Password using the `op` CLI.
// Zero SDK dependencies — requires `op` to be installed and signed in.
//
// References maps env var names to 1Password secret references:
//
//	map[string]string{
//	    "STRIPE_KEY":   "op://Development/Stripe/api-key",
//	    "DATABASE_URL": "op://Development/Postgres/connection-string",
//	}
//
// Each reference uses the `op://vault/item/field` format.
type OnePasswordProvider struct {
	References map[string]string // env var name → op:// reference
}

// NewOnePasswordProvider creates a provider with the given reference map.
// Each key is the env var name, each value is an op:// reference
// (e.g., "op://vault/item/field").
func NewOnePasswordProvider(references map[string]string) *OnePasswordProvider {
	// defensive copy
	refs := make(map[string]string, len(references))
	for k, v := range references {
		refs[k] = v
	}
	return &OnePasswordProvider{References: refs}
}

func (p *OnePasswordProvider) GetAll() (map[string]string, error) {
	if len(p.References) == 0 {
		return map[string]string{}, nil
	}

	if err := checkOPInstalled(); err != nil {
		return nil, err
	}

	secrets := make(map[string]string, len(p.References))
	var errs []string

	for name, ref := range p.References {
		val, err := opRead(ref)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s (%s): %v", name, ref, err))
			continue
		}
		secrets[name] = val
	}

	if len(errs) > 0 {
		return secrets, fmt.Errorf("1password provider: failed to read %d/%d secrets:\n  %s",
			len(errs), len(p.References), strings.Join(errs, "\n  "))
	}

	return secrets, nil
}

func (p *OnePasswordProvider) List() ([]string, error) {
	names := make([]string, 0, len(p.References))
	for k := range p.References {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, nil
}

// checkOPInstalled verifies the `op` CLI is available.
func checkOPInstalled() error {
	_, err := execCommand("op", "--version")
	if err != nil {
		return fmt.Errorf("1password provider: \"op\" CLI not found in PATH — install it from https://1password.com/downloads/command-line")
	}
	return nil
}

// opRead calls `op read <reference>` and returns the secret value.
func opRead(reference string) (string, error) {
	out, err := execCommand("op", "read", reference)
	if err != nil {
		return "", fmt.Errorf("op read failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}
