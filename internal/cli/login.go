package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Reichel1/midsummer/vault-cli/internal/auth"
	"github.com/Reichel1/midsummer/vault-cli/internal/config"
	"github.com/spf13/cobra"
)

const defaultAPIURL = "https://midsummer.new"

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Midsummer AI",
	RunE: func(cmd *cobra.Command, args []string) error {
		apiURL, _ := cmd.Flags().GetString("api-url")
		if apiURL == "" {
			apiURL = defaultAPIURL
		}

		result, err := auth.RunDeviceCodeFlow(apiURL)
		if err != nil {
			return fmt.Errorf("login failed: %w", err)
		}

		// Decode email from the access token payload for display
		email := extractEmailFromJWT(result.AccessToken)

		creds := &config.Credentials{
			APIURL:       apiURL,
			AccessToken:  result.AccessToken,
			RefreshToken: result.RefreshToken,
			Email:        email,
		}

		if err := config.SaveCredentials(creds); err != nil {
			return fmt.Errorf("failed to save credentials: %w", err)
		}

		fmt.Printf("✓ Logged in as %s\n", email)
		return nil
	},
}

func init() {
	loginCmd.Flags().String("api-url", defaultAPIURL, "Midsummer AI API URL")
}

// extractEmailFromJWT extracts email from a JWT payload without verifying the signature.
func extractEmailFromJWT(token string) string {
	parts := splitDot(token)
	if len(parts) != 3 {
		return "user"
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "user"
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Email == "" {
		return "user"
	}

	return claims.Email
}

func splitDot(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}
