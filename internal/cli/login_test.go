package cli

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestExtractEmailFromJWT_ValidToken(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"user@example.com","exp":99999999999}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	token := header + "." + payload + "." + sig

	email := extractEmailFromJWT(token)
	if email != "user@example.com" {
		t.Errorf("expected user@example.com, got %s", email)
	}
}

func TestExtractEmailFromJWT_NoEmail(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"userId":"test","exp":99999999999}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	token := header + "." + payload + "." + sig

	email := extractEmailFromJWT(token)
	if email != "user" {
		t.Errorf("expected fallback 'user', got %s", email)
	}
}

func TestExtractEmailFromJWT_MalformedToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty string", ""},
		{"no dots", "foobar"},
		{"one dot", "foo.bar"},
		{"invalid base64", "a.!!!invalid!!!.c"},
		{"invalid json", "a." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := extractEmailFromJWT(tt.token)
			if email != "user" {
				t.Errorf("expected fallback 'user', got %s", email)
			}
		})
	}
}

func TestSplitDot(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"a.b.c", 3},
		{"a.b.c.d", 4},
		{"nodots", 1},
		{"", 1},
		{"a.", 2},
		{".a", 2},
	}

	for _, tt := range tests {
		parts := splitDot(tt.input)
		if len(parts) != tt.expected {
			t.Errorf("splitDot(%q): expected %d parts, got %d: %v", tt.input, tt.expected, len(parts), parts)
		}
	}
}

// Suppress unused import warning
var _ = json.Marshal
