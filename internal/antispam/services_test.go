package antispam

import (
	"errors"
	"strings"
	"testing"
)

func TestParseUnitShow(t *testing.T) {
	// systemd prints properties in its own order, not the -p order.
	got := ParseUnitShow("User=_rspamd\nLoadState=loaded\nCanReload=yes\n")
	if got["User"] != "_rspamd" || got["LoadState"] != "loaded" || got["CanReload"] != "yes" || len(got) != 3 {
		t.Fatalf("got %v", got)
	}
	if got := ParseUnitShow("User=\nLoadState=not-found\n"); got["User"] != "" || got["LoadState"] != "not-found" {
		t.Fatalf("got %v", got)
	}
}

func TestCheckHostServiceAndLogProblems(t *testing.T) {
	boom := errors.New("boom")
	withLog := func(line string) func(*HostFacts) {
		return func(f *HostFacts) {
			f.EximSettings.Stdout = strings.Replace(eximSettings, "log_file_path = /var/log/exim_%slog", line, 1)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*HostFacts)
		code   string
		sev    Severity
	}{
		{"systemd-run missing", func(f *HostFacts) { f.SystemdRunErr = boom }, CodeSystemd, Temporary},
		{"rspamd unit query failed", func(f *HostFacts) { f.RspamdService.Err = boom }, CodeSystemd, Temporary},
		{"rspamd unit not found", func(f *HostFacts) {
			f.RspamdService.Stdout = "User=\nLoadState=not-found\nCanReload=no\n"
		}, CodeSystemd, Temporary},
		{"exim cannot reload", func(f *HostFacts) {
			f.EximService.Stdout = "User=\nLoadState=loaded\nCanReload=no\n"
		}, CodeSystemd, Definite},
		{"log path not reported", withLog(""), CodeEximLog, Temporary},
		{"log path expansion", withLog("log_file_path = ${if def:x{/a}{/b}}"), CodeEximLog, Temporary},
		{"log path separator", withLog("log_file_path = <; /var/log/exim_%slog"), CodeEximLog, Temporary},
		{"log to syslog only", withLog("log_file_path = syslog"), CodeEximLog, Definite},
		{"log in spool", withLog("log_file_path = /var/spool/exim/log/%slog"), CodeEximLog, Definite},
		{"dated log", withLog("log_file_path = /var/log/exim_%slog-%D"), CodeEximLog, Definite},
		{"monitored log unknown", func(f *HostFacts) { f.MonitoredLog = "" }, CodeEximLog, Temporary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts()
			tc.mutate(&f)
			got := CheckHost(f)
			if len(got) != 1 {
				t.Fatalf("got %d problems %+v, want exactly one %s", len(got), got, tc.code)
			}
			if got[0].Code != tc.code || got[0].Severity != tc.sev {
				t.Errorf("got %s/%d (%s), want %s/%d", got[0].Code, got[0].Severity, got[0].Detail, tc.code, tc.sev)
			}
		})
	}
}

func TestCheckHostAcceptsSyslogDuplication(t *testing.T) {
	f := goodFacts()
	f.EximSettings.Stdout = strings.Replace(eximSettings, "log_file_path = /var/log/exim_%slog", "log_file_path = syslog : /var/log/exim_%slog", 1)
	if got := CheckHost(f); len(got) != 0 {
		t.Fatalf("syslog plus the main log reported %+v", got)
	}
}
