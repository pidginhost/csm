package signatures

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rulesYAML builds a syntactically valid rules file with n distinct rules at
// the given version, so tests can compare an installed file against an update
// by version and rule count.
func rulesYAML(version, n int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "version: %d\nupdated: \"2026-04-11\"\nrules:\n", version)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "  - name: test_rule_%d\n    description: marker %d\n    severity: critical\n    category: webshell\n    file_types: [\".php\"]\n    patterns:\n      - \"TOKEN_%d\"\n    min_match: 1\n", i, i, i)
	}
	return []byte(b.String())
}

func installRules(t *testing.T, rulesDir string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(rulesDir, "malware.yml"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func serveSignedRules(t *testing.T, payload []byte) string {
	t.Helper()
	pubHex, priv := genSigningKey(t)
	swapDefaultTransport(t, routeRoundTripper{routes: map[string]httpTestResponse{
		"/rules.yml":     {body: payload},
		"/rules.yml.sig": {body: sign(priv, payload)},
	}})
	return pubHex
}

func installedRules(t *testing.T, rulesDir string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(rulesDir, "malware.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A validly signed file that carries a fraction of the installed ruleset is a
// rollback (a stale mirror, a replayed old release, a truncated publish), and
// installing it would silently strip detection. The Forge path learned this
// the hard way; the YAML path had no guard at all.
func TestUpdateRefusesRuleCountCollapse(t *testing.T) {
	rulesDir := t.TempDir()
	installed := rulesYAML(7, 20)
	installRules(t, rulesDir, installed)
	pubHex := serveSignedRules(t, rulesYAML(8, 2))

	if _, err := Update(rulesDir, "https://rules.example/rules.yml", pubHex, UpdateOptions{}); err == nil {
		t.Fatal("update that drops 20 rules to 2 was installed")
	} else if !errors.Is(err, ErrUpdateRollback) {
		t.Fatalf("collapse error = %v, want ErrUpdateRollback", err)
	}
	if got := installedRules(t, rulesDir); string(got) != string(installed) {
		t.Fatal("installed rules were replaced despite the refusal")
	}
}

func TestUpdateAllowsConfiguredRuleCountDecrease(t *testing.T) {
	rulesDir := t.TempDir()
	installRules(t, rulesDir, rulesYAML(7, 20))
	pubHex := serveSignedRules(t, rulesYAML(8, 2))

	n, err := Update(rulesDir, "https://rules.example/rules.yml", pubHex, UpdateOptions{
		AllowRuleCountDecrease: true,
	})
	if err != nil {
		t.Fatalf("operator-approved decrease refused: %v", err)
	}
	if n != 2 {
		t.Fatalf("Update returned %d rules, want 2", n)
	}
}

// A signed file whose version is older than the installed one is a replay of
// an old release and must not be installed, whatever its rule count.
func TestUpdateRefusesOlderVersion(t *testing.T) {
	rulesDir := t.TempDir()
	installed := rulesYAML(7, 20)
	installRules(t, rulesDir, installed)
	pubHex := serveSignedRules(t, rulesYAML(6, 20))

	if _, err := Update(rulesDir, "https://rules.example/rules.yml", pubHex, UpdateOptions{}); err == nil {
		t.Fatal("update with an older version than the installed file was installed")
	}
	if got := installedRules(t, rulesDir); string(got) != string(installed) {
		t.Fatal("installed rules were replaced despite the refusal")
	}
}

// Ordinary churn (rules retired, a few removed) must keep flowing.
func TestUpdateAcceptsModestShrink(t *testing.T) {
	rulesDir := t.TempDir()
	installRules(t, rulesDir, rulesYAML(7, 20))
	pubHex := serveSignedRules(t, rulesYAML(8, 15))

	n, err := Update(rulesDir, "https://rules.example/rules.yml", pubHex, UpdateOptions{})
	if err != nil {
		t.Fatalf("modest shrink refused: %v", err)
	}
	if n != 15 {
		t.Fatalf("Update returned %d rules, want 15", n)
	}
}

// A corrupt installed file gives nothing to compare against and must not
// block recovery: the signed update is the way out of that state.
func TestUpdateReplacesUnparsableInstalledRules(t *testing.T) {
	rulesDir := t.TempDir()
	installRules(t, rulesDir, []byte("rules: [\n"))
	pubHex := serveSignedRules(t, rulesYAML(1, 2))

	if _, err := Update(rulesDir, "https://rules.example/rules.yml", pubHex, UpdateOptions{}); err != nil {
		t.Fatalf("recovery update refused: %v", err)
	}
}

// Re-downloading the ruleset that is already installed must leave the file
// alone. Rewriting it moves its mtime, and the daemon treats a changed rules
// file as a reason to rescan every file on the host.
func TestUpdateLeavesIdenticalRulesUntouched(t *testing.T) {
	rulesDir := t.TempDir()
	installed := rulesYAML(7, 20)
	installRules(t, rulesDir, installed)
	path := filepath.Join(rulesDir, "malware.yml")
	old := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	pubHex := serveSignedRules(t, installed)

	n, err := Update(rulesDir, "https://rules.example/rules.yml", pubHex, UpdateOptions{})
	if err != nil {
		t.Fatalf("update with the installed ruleset failed: %v", err)
	}
	if n != 20 {
		t.Fatalf("Update returned %d rules, want 20", n)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(old) {
		t.Fatalf("identical ruleset was rewritten: mtime %v, want %v", info.ModTime(), old)
	}
}
