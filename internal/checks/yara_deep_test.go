package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/yara"
)

type deepYARATestBackend struct {
	err error
}

func (b *deepYARATestBackend) ScanFile(string, int) []yara.Match { return nil }
func (b *deepYARATestBackend) ScanBytes(data []byte) []yara.Match {
	matches, _ := b.ScanBytesChecked(data)
	return matches
}
func (b *deepYARATestBackend) ScanBytesChecked(data []byte) ([]yara.Match, error) {
	if b.err != nil {
		return nil, b.err
	}
	if string(data) == "dormant malware" {
		return []yara.Match{{RuleName: "dormant_webshell", Meta: map[string]string{"severity": "critical"}}}, nil
	}
	return nil, nil
}
func (b *deepYARATestBackend) RuleCount() int { return 1 }
func (b *deepYARATestBackend) Reload() error  { return nil }

func TestCheckYARADeepFindsDormantFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "uploads", "image.dat")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("dormant malware"), 0o600); err != nil {
		t.Fatal(err)
	}
	yara.SetActive(&deepYARATestBackend{})
	t.Cleanup(func() { yara.SetActive(nil) })

	findings := CheckYARADeep(context.Background(), &config.Config{AccountRoots: []string{root}}, nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	if findings[0].Check != "yara_match_scheduled" || findings[0].FilePath != path {
		t.Fatalf("finding = %+v, want YARA match for %s", findings[0], path)
	}
	if findings[0].ContentSHA256 == "" || findings[0].DetectLogic == "" {
		t.Fatalf("YARA finding lacks content fingerprint: %+v", findings[0])
	}
}

func TestCheckYARADeepReportsIncompleteScan(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("clean"), 0o600); err != nil {
		t.Fatal(err)
	}
	yara.SetActive(&deepYARATestBackend{err: errors.New("worker unavailable")})
	t.Cleanup(func() { yara.SetActive(nil) })

	findings := CheckYARADeep(context.Background(), &config.Config{AccountRoots: []string{root}}, nil)
	if len(findings) != 1 || findings[0].Check != "yara_scan_incomplete" {
		t.Fatalf("findings = %+v, want one yara_scan_incomplete finding", findings)
	}
}

func TestYARADeepRunsWithAndWithoutFanotify(t *testing.T) {
	for _, checks := range [][]namedCheck{deepChecks(), reducedDeepChecks()} {
		found := false
		for _, check := range checks {
			if check.name == "yara_deep" {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("yara_deep missing from a scheduled deep-check set")
		}
	}
}

func TestIncompleteCheckDoesNotPurgeLastCompletedFindings(t *testing.T) {
	check := namedCheck{name: "yara_deep", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		markCheckIncomplete(ctx, "yara_deep")
		return []alert.Finding{{Check: "yara_scan_incomplete", Severity: alert.High}}
	}}

	findings, purge := runParallelWithContext(context.Background(), &config.Config{}, nil, []namedCheck{check}, "deep", true)
	if len(findings) != 1 || findings[0].Check != "yara_scan_incomplete" {
		t.Fatalf("findings = %+v, want incomplete finding", findings)
	}
	for _, name := range purge {
		if name == "yara_match_scheduled" || name == "yara_scan_incomplete" || name == "yara_deep" {
			t.Fatalf("incomplete scan included %q in purge list: %v", name, purge)
		}
	}
}

func TestCompletedYARADeepDoesNotOwnRealtimeFindings(t *testing.T) {
	check := namedCheck{name: "yara_deep", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		return nil
	}}

	_, purge := runParallelWithContext(context.Background(), &config.Config{}, nil, []namedCheck{check}, "deep", true)
	if !containsYARAPurgeName(purge, "yara_match_scheduled") {
		t.Fatalf("completed scheduled scan purge list = %v, want yara_match_scheduled", purge)
	}
	if containsYARAPurgeName(purge, "yara_match_realtime") {
		t.Fatalf("scheduled scan owns real-time findings: %v", purge)
	}
}

func TestUnavailableYARADeepPreservesLastScheduledFindings(t *testing.T) {
	originalBackend := activeYARABackend
	originalAvailable := yaraAvailable
	activeYARABackend = func() yara.Backend { return nil }
	yaraAvailable = func() bool { return true }
	t.Cleanup(func() {
		activeYARABackend = originalBackend
		yaraAvailable = originalAvailable
	})
	check := namedCheck{name: "yara_deep", fn: CheckYARADeep}

	findings, purge := runParallelWithContext(context.Background(), &config.Config{}, nil, []namedCheck{check}, "deep", true)
	if len(findings) != 1 || findings[0].Check != "yara_scan_incomplete" {
		t.Fatalf("unavailable YARA findings = %+v, want yara_scan_incomplete", findings)
	}
	if containsYARAPurgeName(purge, "yara_match_scheduled") {
		t.Fatalf("unavailable YARA backend purged prior findings: %v", purge)
	}
}

func containsYARAPurgeName(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
