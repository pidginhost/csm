package signatures

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Update downloads the latest rules from the configured URL.
// Validates the downloaded rules before installing.
// A detached ed25519 signature is fetched from url+".sig" and verified
// before the rules are installed.
// Returns the number of rules loaded, or error.
func Update(rulesDir, url, signingKey string) (int, error) {
	if url == "" {
		return 0, fmt.Errorf("no update URL configured (set signatures.update_url in csm.yaml)")
	}
	if err := requireSigningKey(signingKey); err != nil {
		return 0, err
	}

	// Download
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("downloading rules from %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("download failed: HTTP %d from %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // max 10MB
	if err != nil {
		return 0, fmt.Errorf("reading response: %w", err)
	}

	sig, err := fetchSignature(url + ".sig")
	if err != nil {
		return 0, fmt.Errorf("signature verification required but failed: %w", err)
	}
	if err := VerifySignature(signingKey, data, sig); err != nil {
		return 0, fmt.Errorf("rules signature invalid: %w", err)
	}

	// Validate: must parse as valid YAML rules
	var rf RuleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return 0, fmt.Errorf("invalid rules file: %w", err)
	}
	if len(rf.Rules) == 0 {
		return 0, fmt.Errorf("rules file contains no rules")
	}

	// Validate each rule compiles
	for _, rule := range rf.Rules {
		if err := rule.compile(); err != nil {
			return 0, fmt.Errorf("rule '%s' failed validation: %w", rule.Name, err)
		}
	}

	// Ensure rules directory exists
	if err := os.MkdirAll(rulesDir, 0700); err != nil {
		return 0, fmt.Errorf("creating rules dir: %w", err)
	}

	// Atomic write: temp file + rename
	destPath := filepath.Join(rulesDir, "malware.yml")
	tmpPath := destPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return 0, fmt.Errorf("writing rules: %w", err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return 0, fmt.Errorf("installing rules: %w", err)
	}

	return len(rf.Rules), nil
}
