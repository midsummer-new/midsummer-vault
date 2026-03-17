package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Reichel1/midsummer/vault-cli/internal/config"
)

func makeJWT(exp int64, claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	if claims == nil {
		claims = make(map[string]interface{})
	}
	claims["exp"] = exp
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))
	return header + "." + payload + "." + sig
}

func validJWT() string {
	return makeJWT(time.Now().Add(1*time.Hour).Unix(), map[string]interface{}{
		"userId":    "test-user",
		"tokenType": "access",
	})
}

func expiredJWT() string {
	return makeJWT(time.Now().Add(-1*time.Hour).Unix(), map[string]interface{}{
		"userId":    "test-user",
		"tokenType": "access",
	})
}

func TestGetSecrets_Success(t *testing.T) {
	secrets := map[string]string{
		"STRIPE_KEY": "sk_live_123",
		"DB_URL":     "postgres://localhost/db",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/vault/proj_123/secrets" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			t.Error("missing Authorization header")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"secrets": secrets})
	}))
	defer server.Close()

	creds := &config.Credentials{
		APIURL:      server.URL,
		AccessToken: validJWT(),
	}
	client, err := NewClientDirect(creds)
	if err != nil {
		t.Fatal(err)
	}

	result, err := client.GetSecrets("proj_123")
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range secrets {
		if result[k] != v {
			t.Errorf("secret %s: got %q, want %q", k, result[k], v)
		}
	}
}

func TestGetSecrets_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"invalid token"}`))
	}))
	defer server.Close()

	creds := &config.Credentials{
		APIURL:      server.URL,
		AccessToken: validJWT(),
	}
	client, _ := NewClientDirect(creds)

	_, err := client.GetSecrets("proj_123")
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if got := err.Error(); got != `API error 401: {"error":"invalid token"}` {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestGetSecrets_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	creds := &config.Credentials{APIURL: server.URL, AccessToken: validJWT()}
	client, _ := NewClientDirect(creds)

	_, err := client.GetSecrets("proj_123")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestGetSecrets_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>Not Found</html>"))
	}))
	defer server.Close()

	creds := &config.Credentials{APIURL: server.URL, AccessToken: validJWT()}
	client, _ := NewClientDirect(creds)

	_, err := client.GetSecrets("proj_123")
	if err == nil {
		t.Fatal("expected error for HTML response")
	}
}

func TestGetSecrets_EmptySecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"secrets": map[string]string{}})
	}))
	defer server.Close()

	creds := &config.Credentials{APIURL: server.URL, AccessToken: validJWT()}
	client, _ := NewClientDirect(creds)

	result, err := client.GetSecrets("proj_123")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty map, got %v", result)
	}
}

func TestGetSecretNames_Success(t *testing.T) {
	names := []string{"STRIPE_KEY", "DB_URL", "RESEND_API_KEY"}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("names_only") != "true" {
			t.Error("expected names_only=true query param")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"names": names})
	}))
	defer server.Close()

	creds := &config.Credentials{APIURL: server.URL, AccessToken: validJWT()}
	client, _ := NewClientDirect(creds)

	result, err := client.GetSecretNames("proj_123")
	if err != nil {
		t.Fatal(err)
	}

	if len(result) != len(names) {
		t.Fatalf("expected %d names, got %d", len(names), len(result))
	}
	for i, n := range names {
		if result[i] != n {
			t.Errorf("name[%d]: got %q, want %q", i, result[i], n)
		}
	}
}

func TestGetSecretNames_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer server.Close()

	creds := &config.Credentials{APIURL: server.URL, AccessToken: validJWT()}
	client, _ := NewClientDirect(creds)

	_, err := client.GetSecretNames("proj_123")
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
}

func TestRefreshTokens_Success(t *testing.T) {
	newAccess := validJWT()
	newRefresh := makeJWT(time.Now().Add(30*24*time.Hour).Unix(), map[string]interface{}{
		"tokenType": "refresh",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/auth/token" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var body struct {
			RefreshToken string `json:"refreshToken"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.RefreshToken == "" {
			t.Error("missing refreshToken in request body")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"accessToken":  newAccess,
			"refreshToken": newRefresh,
		})
	}))
	defer server.Close()

	// Set up temp config dir for SaveCredentials
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	configDir := filepath.Join(tmpDir, ".config", "midsummerai", "vault")
	os.MkdirAll(configDir, 0755)

	creds := &config.Credentials{
		APIURL:       server.URL,
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
	}
	client := &Client{
		apiURL:     server.URL,
		httpClient: http.DefaultClient,
		creds:      creds,
	}

	err := client.RefreshTokens()
	if err != nil {
		t.Fatal(err)
	}

	if client.creds.AccessToken != newAccess {
		t.Error("access token not updated")
	}
	if client.creds.RefreshToken != newRefresh {
		t.Error("refresh token not updated")
	}
}

func TestRefreshTokens_ServerRejects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer server.Close()

	creds := &config.Credentials{
		APIURL:       server.URL,
		AccessToken:  "old",
		RefreshToken: "bad-refresh",
	}
	client := &Client{
		apiURL:     server.URL,
		httpClient: http.DefaultClient,
		creds:      creds,
	}

	err := client.RefreshTokens()
	if err == nil {
		t.Fatal("expected error for 401 refresh response")
	}
}

func TestNewClient_ExpiredToken_AutoRefreshes(t *testing.T) {
	newAccess := validJWT()
	newRefresh := makeJWT(time.Now().Add(30*24*time.Hour).Unix(), nil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"accessToken":  newAccess,
			"refreshToken": newRefresh,
		})
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)
	os.MkdirAll(filepath.Join(tmpDir, ".config", "midsummerai", "vault"), 0755)

	creds := &config.Credentials{
		APIURL:       server.URL,
		AccessToken:  expiredJWT(),
		RefreshToken: "valid-refresh",
	}

	client, err := NewClient(creds)
	if err != nil {
		t.Fatal(err)
	}

	if client.creds.AccessToken != newAccess {
		t.Error("NewClient did not auto-refresh expired token")
	}
}

func TestNewClient_ExpiredToken_RefreshFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer server.Close()

	creds := &config.Credentials{
		APIURL:       server.URL,
		AccessToken:  expiredJWT(),
		RefreshToken: "bad-refresh",
	}

	_, err := NewClient(creds)
	if err == nil {
		t.Fatal("expected error when refresh fails")
	}
}

func TestGetSecrets_BearerTokenSent(t *testing.T) {
	token := validJWT()
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"secrets": map[string]string{}})
	}))
	defer server.Close()

	creds := &config.Credentials{APIURL: server.URL, AccessToken: token}
	client, _ := NewClientDirect(creds)
	client.GetSecrets("proj_123")

	expected := fmt.Sprintf("Bearer %s", token)
	if receivedAuth != expected {
		t.Errorf("expected Authorization: %q, got %q", expected, receivedAuth)
	}
}

func TestGetSecrets_NetworkError(t *testing.T) {
	creds := &config.Credentials{APIURL: "http://127.0.0.1:1", AccessToken: validJWT()}
	client, _ := NewClientDirect(creds)

	_, err := client.GetSecrets("proj_123")
	if err == nil {
		t.Fatal("expected network error")
	}
}
