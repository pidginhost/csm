package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// Two checks often flag the same file. The second finding must not be
// reported as a failed move ("file not found") after the first one already
// moved the file; it refers to a file this job has quarantined.
func TestScanJobQuarantineSamePathReportedOnce(t *testing.T) {
	qdir := t.TempDir()
	src := filepath.Join(t.TempDir(), "shell.php")
	if err := os.WriteFile(src, []byte("<?php system($_POST['c']);"), 0o644); err != nil {
		t.Fatal(err)
	}

	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	calls := 0
	inner := fakeQuarantineFile(qdir)
	m.quarantineFile = func(f alert.Finding) (checks.RemediationResult, bool) {
		calls++
		return inner(f)
	}
	m.runAccountScan = func(context.Context, *config.Config, *state.Store, string, checks.AccountScanOptions) []alert.Finding {
		return []alert.Finding{
			{Severity: alert.Critical, Check: "webshell", FilePath: src},
			{Severity: alert.Critical, Check: "obfuscated_php", FilePath: src},
		}
	}

	id, err := m.Enqueue("account", "acct", checks.AccountScanOptions{}, true)
	if err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, id, "done", 5*time.Second)

	findings, _, err := db.ListScanJobFindings(id, 0, 0)
	if err != nil || len(findings) != 2 {
		t.Fatalf("findings = %d err = %v, want 2", len(findings), err)
	}
	for _, f := range findings {
		if f.RemediationStatus != "quarantined" {
			t.Errorf("%s: status = %q detail = %q, want quarantined", f.Check, f.RemediationStatus, f.RemediationDetail)
		}
	}
	if calls != 1 {
		t.Errorf("quarantine attempted %d times for one path, want 1", calls)
	}
}

func TestScanJobCleanedPathReportedOnce(t *testing.T) {
	st, db := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	calls := 0
	m.quarantineFile = func(f alert.Finding) (checks.RemediationResult, bool) {
		calls++
		return checks.RemediationResult{
			Success:           true,
			Action:            "cleaned " + f.FilePath + " in place",
			RemediationStatus: "cleaned",
		}, true
	}
	m.runAccountScan = func(context.Context, *config.Config, *state.Store, string, checks.AccountScanOptions) []alert.Finding {
		return []alert.Finding{
			{Severity: alert.Critical, Check: "obfuscated_php", FilePath: "/home/acct/public_html/wp-content/plugins/example/plugin.php"},
			{Severity: alert.Critical, Check: "suspicious_php_content", FilePath: "/home/acct/public_html/wp-content/plugins/example/plugin.php"},
		}
	}

	id, err := m.Enqueue("account", "acct", checks.AccountScanOptions{}, true)
	if err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, id, "done", 5*time.Second)

	findings, _, err := db.ListScanJobFindings(id, 0, 0)
	if err != nil || len(findings) != 2 {
		t.Fatalf("findings = %d err = %v, want 2", len(findings), err)
	}
	for _, f := range findings {
		if f.RemediationStatus != "cleaned" {
			t.Errorf("%s: status = %q detail = %q, want cleaned", f.Check, f.RemediationStatus, f.RemediationDetail)
		}
	}
	if calls != 1 {
		t.Errorf("clean attempted %d times for one path, want 1", calls)
	}
}
