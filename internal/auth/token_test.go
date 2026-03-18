package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func makeTestJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"exp":%d,"userId":"test"}`, exp),
	))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	return header + "." + payload + "." + sig
}

func TestIsTokenExpired_ValidFutureToken(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	if IsTokenExpired(token) {
		t.Error("expected token to not be expired")
	}
}

func TestIsTokenExpired_ExpiredToken(t *testing.T) {
	token := makeTestJWT(time.Now().Add(-1 * time.Hour).Unix())
	if !IsTokenExpired(token) {
		t.Error("expected token to be expired")
	}
}

func TestIsTokenExpired_Buffer(t *testing.T) {
	// Token expires in 20 seconds — should be treated as expired (30s buffer)
	token := makeTestJWT(time.Now().Add(20 * time.Second).Unix())
	if !IsTokenExpired(token) {
		t.Error("expected token within buffer zone to be treated as expired")
	}
}

func TestIsTokenExpired_MalformedToken(t *testing.T) {
	if !IsTokenExpired("not-a-jwt") {
		t.Error("expected malformed token to be treated as expired")
	}
}

func TestIsTokenExpired_EmptyToken(t *testing.T) {
	if !IsTokenExpired("") {
		t.Error("expected empty token to be treated as expired")
	}
}

func TestSplitJWT(t *testing.T) {
	parts := splitJWT("a.b.c")
	if len(parts) != 3 || parts[0] != "a" || parts[1] != "b" || parts[2] != "c" {
		t.Errorf("unexpected split result: %v", parts)
	}

	if splitJWT("a.b") != nil {
		t.Error("expected nil for 2-part token")
	}

	if splitJWT("abcdef") != nil {
		t.Error("expected nil for no-dot token")
	}
}

// Suppress unused import warning
var _ = json.Marshal
