package store

// Provider is the interface for secret backends.
// The local encrypted store is one implementation.
// Enterprise teams can implement this for AWS Secrets Manager,
// HashiCorp Vault, 1Password, etc.
type Provider interface {
	// GetAll returns all secrets as key-value pairs.
	GetAll() (map[string]string, error)

	// List returns secret names without values.
	List() ([]string, error)
}

// Ensure Store implements Provider.
var _ Provider = (*Store)(nil)

// ProviderFunc wraps a function as a Provider (for simple integrations).
type ProviderFunc struct {
	GetAllFn func() (map[string]string, error)
	ListFn   func() ([]string, error)
}

func (f ProviderFunc) GetAll() (map[string]string, error) { return f.GetAllFn() }
func (f ProviderFunc) List() ([]string, error)            { return f.ListFn() }

// EnvProvider reads secrets from a specific env var prefix.
// e.g., VAULT_SECRET_STRIPE_KEY=sk_live_... → STRIPE_KEY=sk_live_...
// Useful for companies that inject secrets via their existing CI/CD.
type EnvProvider struct {
	Prefix string // e.g., "VAULT_SECRET_"
}

func (p EnvProvider) GetAll() (map[string]string, error) {
	return envWithPrefix(p.Prefix), nil
}

func (p EnvProvider) List() ([]string, error) {
	secrets := envWithPrefix(p.Prefix)
	names := make([]string, 0, len(secrets))
	for k := range secrets {
		names = append(names, k)
	}
	return names, nil
}
