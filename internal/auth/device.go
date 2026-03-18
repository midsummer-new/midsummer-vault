package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/browser"
)

// DeviceCodeResult contains the tokens received after device code approval.
type DeviceCodeResult struct {
	AccessToken  string
	RefreshToken string
}

type createCodeResponse struct {
	Code         string `json:"code"`
	ExpiresAt    int64  `json:"expiresAt"`
	Interval     int    `json:"interval"`
	AuthorizeURL string `json:"authorizeUrl"`
}

type pollResponse struct {
	Status       string `json:"status"`
	AccessToken  string `json:"accessToken,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
	Error        string `json:"error,omitempty"`
}

// RunDeviceCodeFlow starts the device code auth flow:
// 1. POST to create a device code
// 2. Print instructions and try to open the browser
// 3. Poll until approved, expired, or timeout
func RunDeviceCodeFlow(apiURL string) (*DeviceCodeResult, error) {
	// Step 1: Create device code
	resp, err := http.Post(apiURL+"/api/auth/device/code", "application/json", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create device code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var codeResp createCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&codeResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Step 2: Print instructions
	fmt.Printf("\n  Open this URL in your browser:\n")
	fmt.Printf("  %s\n\n", codeResp.AuthorizeURL)
	fmt.Printf("  Then enter this code:\n")
	fmt.Printf("  %s\n\n", codeResp.Code)

	// Try to open browser (non-blocking, ignore errors)
	_ = browser.OpenURL(codeResp.AuthorizeURL)

	fmt.Printf("Waiting for authorization...")

	// Step 3: Poll
	interval := time.Duration(codeResp.Interval) * time.Second
	if interval < time.Second {
		interval = 2 * time.Second
	}
	deadline := time.Now().Add(5 * time.Minute)

	for time.Now().Before(deadline) {
		time.Sleep(interval)

		result, status, err := pollDeviceCode(apiURL, codeResp.Code)
		if err != nil {
			// Network error — keep trying
			continue
		}

		switch status {
		case "approved":
			fmt.Printf(" done!\n")
			return result, nil
		case "expired":
			fmt.Printf(" expired.\n")
			return nil, fmt.Errorf("device code expired — please try again")
		case "pending":
			// Keep polling
			continue
		default:
			fmt.Printf(" failed.\n")
			return nil, fmt.Errorf("unexpected status: %s", status)
		}
	}

	fmt.Printf(" timed out.\n")
	return nil, fmt.Errorf("login timed out after 5 minutes")
}

func pollDeviceCode(apiURL, code string) (*DeviceCodeResult, string, error) {
	body, _ := json.Marshal(map[string]string{"code": code})
	resp, err := http.Post(apiURL+"/api/auth/device/poll", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	var pollResp pollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
		return nil, "", err
	}

	if pollResp.Status == "approved" && pollResp.AccessToken != "" {
		return &DeviceCodeResult{
			AccessToken:  pollResp.AccessToken,
			RefreshToken: pollResp.RefreshToken,
		}, "approved", nil
	}

	return nil, pollResp.Status, nil
}
