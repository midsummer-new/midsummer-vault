package store

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
)

// AWSSecretsManagerProvider reads secrets from AWS Secrets Manager
// by shelling out to the `aws` CLI. Zero SDK dependencies.
//
// The secret value must be a JSON object of key-value string pairs:
//
//	{"STRIPE_KEY": "sk_live_...", "DATABASE_URL": "postgres://..."}
type AWSSecretsManagerProvider struct {
	SecretID string // AWS secret name or ARN
	Region   string // optional — falls back to AWS_REGION / AWS_DEFAULT_REGION env
}

// NewAWSSecretsManagerProvider creates a provider for the given secret.
// Region is optional — leave empty to use the AWS CLI's default resolution
// (AWS_REGION env, ~/.aws/config, etc.).
func NewAWSSecretsManagerProvider(secretID, region string) *AWSSecretsManagerProvider {
	return &AWSSecretsManagerProvider{
		SecretID: secretID,
		Region:   region,
	}
}

func (p *AWSSecretsManagerProvider) GetAll() (map[string]string, error) {
	if p.SecretID == "" {
		return nil, fmt.Errorf("aws provider: secretId is required")
	}

	args := []string{
		"secretsmanager", "get-secret-value",
		"--secret-id", p.SecretID,
		"--output", "json",
	}
	if p.Region != "" {
		args = append(args, "--region", p.Region)
	}

	out, err := execCommand("aws", args...)
	if err != nil {
		return nil, fmt.Errorf("aws provider: %w", err)
	}

	// AWS CLI returns {"SecretString": "{\"KEY\":\"value\"}", ...}
	var response struct {
		SecretString string `json:"SecretString"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		return nil, fmt.Errorf("aws provider: parse response: %w", err)
	}

	if response.SecretString == "" {
		return nil, fmt.Errorf("aws provider: secret %q has no SecretString (binary secrets not supported)", p.SecretID)
	}

	var secrets map[string]string
	if err := json.Unmarshal([]byte(response.SecretString), &secrets); err != nil {
		return nil, fmt.Errorf("aws provider: SecretString is not a JSON object of key-value strings: %w", err)
	}

	return secrets, nil
}

func (p *AWSSecretsManagerProvider) List() ([]string, error) {
	secrets, err := p.GetAll()
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(secrets))
	for k := range secrets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, nil
}

// execCommand runs an external CLI tool and returns stdout.
// Uses exec.Command (no shell) to avoid injection.
func execCommand(name string, args ...string) ([]byte, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%q not found in PATH — install it first", name)
	}

	cmd := exec.Command(path, args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("%s failed: %s", name, string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("%s failed: %w", name, err)
	}

	return out, nil
}
