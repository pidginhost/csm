package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func TestSensitiveWatchsetGlobsExpand(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(p string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(filepath.Join(root, "etc/shadow"))
	mustWrite(filepath.Join(root, "etc/sudoers.d/dropin1"))
	mustWrite(filepath.Join(root, "etc/sudoers.d/dropin2"))
	mustWrite(filepath.Join(root, "etc/cron.d/anacron"))

	got := ExpandWatchset(root)

	want := map[string]bool{
		"etc/shadow":            true,
		"etc/sudoers.d/dropin1": true,
		"etc/sudoers.d/dropin2": true,
		"etc/cron.d/anacron":    true,
	}
	for _, p := range got {
		rel, _ := filepath.Rel(root, p)
		delete(want, rel)
	}
	if len(want) != 0 {
		t.Fatalf("watchset missing entries: %+v (got: %+v)", want, got)
	}
}

func disableSensitiveProvenanceForTest(t *testing.T) {
	t.Helper()
	oldLogs := pkgManagerLogs
	oldProbe := AncestryProbe
	pkgManagerLogs = []string{filepath.Join(t.TempDir(), "missing-package-manager.log")}
	AncestryProbe = nil
	t.Cleanup(func() {
		pkgManagerLogs = oldLogs
		AncestryProbe = oldProbe
	})
}

func TestEvaluateSensitiveFileWrite(t *testing.T) {
	disableSensitiveProvenanceForTest(t)

	cases := []struct {
		name        string
		uid         uint32
		path        string
		wantFinding bool
		wantSev     alert.Severity
	}{
		{"shadow_write_root", 0, "/etc/shadow", true, alert.High},
		{"shadow_write_user", 1000, "/etc/shadow", true, alert.Critical},
		{"sudoers_d_root", 0, "/etc/sudoers.d/91-extra", true, alert.High},
		{"sshd_config_user", 1000, "/etc/ssh/sshd_config", true, alert.Critical},
		{"crontab_user_root", 0, "/var/spool/cron/root", true, alert.High},
		{"unknown_path_returns_false", 1000, "/tmp/x", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := EvaluateSensitiveFileWrite(tc.path, tc.uid, 1234, "writer")
			if ok != tc.wantFinding {
				t.Fatalf("got finding=%v, want %v", ok, tc.wantFinding)
			}
			if ok && f.Severity != tc.wantSev {
				t.Fatalf("Severity = %v, want %v", f.Severity, tc.wantSev)
			}
		})
	}
}

func TestEvaluateSensitiveFileAppearance(t *testing.T) {
	disableSensitiveProvenanceForTest(t)

	before := time.Now()
	f, ok := EvaluateSensitiveFileAppearance("/etc/cron.d/evil")
	after := time.Now()
	if !ok {
		t.Fatal("expected finding for new cron drop-in")
	}
	if f.Check != "sensitive_file_modified" || f.Severity != alert.High {
		t.Fatalf("unexpected finding: %+v", f)
	}
	if f.FilePath != "/etc/cron.d/evil" {
		t.Errorf("FilePath = %q, want /etc/cron.d/evil", f.FilePath)
	}
	if f.Timestamp.IsZero() {
		t.Error("Timestamp must be set, got zero value (renders as 0001-01-01 00:00:00 in alerts)")
	}
	if f.Timestamp.Before(before) || f.Timestamp.After(after) {
		t.Errorf("Timestamp %s outside test window [%s, %s]", f.Timestamp, before, after)
	}
}

func TestCheckSensitiveFilesAlertsOnNewGlobAfterBaseline(t *testing.T) {
	root := t.TempDir()
	oldWatchset := sensitiveWatchset
	sensitiveWatchset = []string{filepath.Join(root, "etc/cron.d/*")}
	t.Cleanup(func() { sensitiveWatchset = oldWatchset })

	if err := os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0o755); err != nil {
		t.Fatal(err)
	}

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if got := CheckSensitiveFiles(context.Background(), &config.Config{}, st); len(got) != 0 {
		t.Fatalf("baseline run emitted findings: %+v", got)
	}

	if err := os.WriteFile(filepath.Join(root, "etc/cron.d/evil"), []byte("* * * * * root true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := CheckSensitiveFiles(context.Background(), &config.Config{}, st)
	if len(got) != 1 {
		t.Fatalf("new glob file should emit one finding, got %+v", got)
	}
	if got[0].Check != "sensitive_file_modified" {
		t.Fatalf("Check = %q, want sensitive_file_modified", got[0].Check)
	}
}

// TestCheckSensitiveFilesHashDiffSetsTimestampAndPath guards against the
// previous bug where the periodic hash-change emitter left Timestamp
// unset (rendered as `0001-01-01 00:00:00` in alerts) and FilePath empty,
// preventing alert renderers and downstream correlators from grouping
// the finding alongside other modifications of the same path.
func TestCheckSensitiveFilesHashDiffSetsTimestampAndPath(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "etc/shadow")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("root:x:0:0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldWatchset := sensitiveWatchset
	sensitiveWatchset = []string{target}
	t.Cleanup(func() { sensitiveWatchset = oldWatchset })

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if got := CheckSensitiveFiles(context.Background(), &config.Config{}, st); len(got) != 0 {
		t.Fatalf("baseline run emitted findings: %+v", got)
	}

	if err := os.WriteFile(target, []byte("root:!:0:0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	before := time.Now()
	got := CheckSensitiveFiles(context.Background(), &config.Config{}, st)
	after := time.Now()

	if len(got) != 1 {
		t.Fatalf("hash diff should emit one finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Timestamp.IsZero() {
		t.Errorf("Timestamp must be set, got zero value (renders as 0001-01-01 00:00:00 in alerts)")
	}
	if f.Timestamp.Before(before) || f.Timestamp.After(after) {
		t.Errorf("Timestamp %s outside test window [%s, %s]", f.Timestamp, before, after)
	}
	if f.FilePath != target {
		t.Errorf("FilePath = %q, want %q", f.FilePath, target)
	}
}
