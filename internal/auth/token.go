package auth

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// jwtClaims is the minimal set of JWT claims we need to check expiry.
type jwtClaims struct {
	Exp int64 `json:"exp"`
}

// IsTokenExpired checks if a JWT has expired (with 30s buffer).
// Only reads the payload — does NOT verify the signature.
func IsTokenExpired(token string) bool {
	parts := splitJWT(token)
	if parts == nil {
		return true
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return true
	}

	var claims jwtClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return true
	}

	// Treat as expired 30s before actual expiry to avoid race conditions
	return time.Now().Unix() >= claims.Exp-30
}

// splitJWT splits a JWT into its 3 parts. Returns nil if malformed.
func splitJWT(token string) []string {
	var parts []string
	start := 0
	count := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
			count++
		}
	}
	parts = append(parts, token[start:])
	if len(parts) != 3 {
		return nil
	}
	return parts
}
