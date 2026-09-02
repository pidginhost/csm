package signatures

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/pidginhost/csm/internal/atomicio"
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

	destPath := filepath.Join(rulesDir, "malware.yml")
	if err := refuseRollback(destPath, rf); err != nil {
		return 0, err
	}

	// Ensure rules directory exists
	if err := os.MkdirAll(rulesDir, 0700); err != nil {
		return 0, fmt.Errorf("creating rules dir: %w", err)
	}

	// Atomic write: write-temp, fsync, rename, dir-fsync. The daemon reloads
	// these rules on the next tick, so a torn write must never be observable.
	if err := atomicio.AtomicWrite(destPath, 0600, data); err != nil {
		return 0, fmt.Errorf("installing rules: %w", err)
	}

	return len(rf.Rules), nil
}

// refuseRollback rejects a validly signed update that would move the
// installed ruleset backwards: an older version number is a replayed release,
// and a rule count that collapses to under half of what is installed is a
// stale mirror or a truncated publish rather than ordinary churn. Either
// would silently strip detection while reporting a successful update. A
// missing or unparsable installed file gives nothing to compare against and
// is not protected: the signed update is the recovery path out of that state.
func refuseRollback(destPath string, next RuleFile) error {
	current, err := os.ReadFile(destPath) // #nosec G304 -- operator-configured rules dir.
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading installed rules: %w", err)
	}
	installed, ok := parseInstalledRules(current)
	if !ok {
		return nil
	}
	if next.Version < installed.Version {
		return fmt.Errorf("refusing rules downgrade: update is version %d, installed rules are version %d", next.Version, installed.Version)
	}
	if len(next.Rules)*2 < len(installed.Rules) {
		return fmt.Errorf("refusing rules rollback: update carries %d rules, installed rules carry %d", len(next.Rules), len(installed.Rules))
	}
	return nil
}

// parseInstalledRules reports false for an unparsable or empty installed
// file: the states a signed update must be allowed to repair.
func parseInstalledRules(data []byte) (RuleFile, bool) {
	var installed RuleFile
	if yaml.Unmarshal(data, &installed) != nil || len(installed.Rules) == 0 {
		return RuleFile{}, false
	}
	return installed, true
}
