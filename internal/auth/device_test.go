package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPollDeviceCode_Approved(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/auth/device/poll" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["code"] != "ABCD-1234" {
			t.Errorf("unexpected code: %s", body["code"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pollResponse{
			Status:       "approved",
			AccessToken:  "access-token-123",
			RefreshToken: "refresh-token-456",
		})
	}))
	defer server.Close()

	result, status, err := pollDeviceCode(server.URL, "ABCD-1234")
	if err != nil {
		t.Fatal(err)
	}
	if status != "approved" {
		t.Errorf("expected approved, got %s", status)
	}
	if result.AccessToken != "access-token-123" {
		t.Errorf("unexpected access token: %s", result.AccessToken)
	}
	if result.RefreshToken != "refresh-token-456" {
		t.Errorf("unexpected refresh token: %s", result.RefreshToken)
	}
}

func TestPollDeviceCode_Pending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pollResponse{Status: "pending"})
	}))
	defer server.Close()

	result, status, err := pollDeviceCode(server.URL, "ABCD-1234")
	if err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Errorf("expected pending, got %s", status)
	}
	if result != nil {
		t.Error("expected nil result for pending status")
	}
}

func TestPollDeviceCode_Expired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pollResponse{Status: "expired"})
	}))
	defer server.Close()

	result, status, err := pollDeviceCode(server.URL, "ABCD-1234")
	if err != nil {
		t.Fatal(err)
	}
	if status != "expired" {
		t.Errorf("expected expired, got %s", status)
	}
	if result != nil {
		t.Error("expected nil result for expired status")
	}
}

func TestPollDeviceCode_NetworkError(t *testing.T) {
	_, _, err := pollDeviceCode("http://127.0.0.1:1", "ABCD-1234")
	if err == nil {
		t.Fatal("expected network error")
	}
}

func TestPollDeviceCode_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>error</html>"))
	}))
	defer server.Close()

	_, _, err := pollDeviceCode(server.URL, "ABCD-1234")
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
}

func TestPollDeviceCode_ApprovedButNoTokens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pollResponse{Status: "approved"})
	}))
	defer server.Close()

	result, status, err := pollDeviceCode(server.URL, "ABCD-1234")
	if err != nil {
		t.Fatal(err)
	}
	// When accessToken is empty, it should not return a result even if status says approved
	if status != "approved" {
		t.Errorf("expected approved, got %s", status)
	}
	if result != nil {
		t.Error("expected nil result when accessToken is empty")
	}
}

func TestPollDeviceCode_TransitionFromPendingToApproved(t *testing.T) {
	var callCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")

		if count < 3 {
			json.NewEncoder(w).Encode(pollResponse{Status: "pending"})
		} else {
			json.NewEncoder(w).Encode(pollResponse{
				Status:       "approved",
				AccessToken:  "final-access",
				RefreshToken: "final-refresh",
			})
		}
	}))
	defer server.Close()

	// Simulate polling loop (what RunDeviceCodeFlow does)
	var result *DeviceCodeResult
	for i := 0; i < 5; i++ {
		r, status, err := pollDeviceCode(server.URL, "TEST-0001")
		if err != nil {
			t.Fatal(err)
		}
		if status == "approved" {
			result = r
			break
		}
	}

	if result == nil {
		t.Fatal("never received approved status")
	}
	if result.AccessToken != "final-access" {
		t.Errorf("unexpected access token: %s", result.AccessToken)
	}
}
