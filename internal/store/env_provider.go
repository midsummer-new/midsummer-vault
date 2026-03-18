package store

import (
	"os"
	"strings"
)

// envWithPrefix reads env vars with the given prefix and strips it.
// VAULT_SECRET_STRIPE_KEY=sk_live_... → STRIPE_KEY=sk_live_...
func envWithPrefix(prefix string) map[string]string {
	result := make(map[string]string)
	for _, env := range os.Environ() {
		idx := strings.IndexByte(env, '=')
		if idx < 0 {
			continue
		}
		key := env[:idx]
		if strings.HasPrefix(key, prefix) {
			name := key[len(prefix):]
			if name != "" {
				result[name] = env[idx+1:]
			}
		}
	}
	return result
}
