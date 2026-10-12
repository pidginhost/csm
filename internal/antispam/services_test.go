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
	got = ParseUnitShow("User=\nLoadState=not-found\n")
	user, present := got["User"]
	if !present || user != "" || got["LoadState"] != "not-found" || len(got) != 2 {
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
		{"rspamd reload not reported", func(f *HostFacts) {
			f.RspamdService.Stdout = "User=_rspamd\nLoadState=loaded\n"
		}, CodeSystemd, Temporary},
		{"exim reload empty", func(f *HostFacts) {
			f.EximService.Stdout = "LoadState=loaded\nCanReload=\n"
		}, CodeSystemd, Temporary},
		{"exim reload unreadable", func(f *HostFacts) {
			f.EximService.Stdout = "LoadState=loaded\nCanReload=unknown\n"
		}, CodeSystemd, Temporary},
		{"log path not reported", withLog(""), CodeEximLog, Temporary},
		{"log uses build default", withLog("log_file_path ="), CodeEximLog, Temporary},
		{"log duplicates build default", withLog("log_file_path = : syslog"), CodeEximLog, Temporary},
		{"build default after syslog", withLog("log_file_path = syslog : :"), CodeEximLog, Temporary},
		{"build default before monitored path", withLog("log_file_path = : /var/log/exim_%slog"), CodeEximLog, Temporary},
		{"log path expansion", withLog("log_file_path = ${if def:x{/a}{/b}}"), CodeEximLog, Temporary},
		{"log path separator", withLog("log_file_path = <; /var/log/exim_%slog"), CodeEximLog, Temporary},
		{"log to syslog only", withLog("log_file_path = syslog"), CodeEximLog, Definite},
		{"syslog with trailing separator", withLog("log_file_path = syslog :"), CodeEximLog, Definite},
		{"log in spool", withLog("log_file_path = /var/spool/exim/log/%slog"), CodeEximLog, Definite},
		{"dated log", withLog("log_file_path = /var/log/exim_%slog-%D"), CodeEximLog, Definite},
		{"monitored path ignored", withLog("log_file_path = /var/log/other_%slog : /var/log/exim_%slog"), CodeEximLog, Definite},
		{"escaped colon in path", withLog("log_file_path = /var/log/other::/var/log/exim_%slog"), CodeEximLog, Definite},
		{"escaped colon after syslog", withLog("log_file_path = syslog::/var/log/exim_%slog"), CodeEximLog, Definite},
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

func TestCheckHostUsesFirstLogDestination(t *testing.T) {
	for _, raw := range []string{
		"/var/log/exim_%slog : /var/log/other_%slog",
		"syslog : /var/log/exim_%slog : /var/log/other_%slog",
		"syslog : syslog : /var/log/exim_%slog",
	} {
		t.Run(raw, func(t *testing.T) {
			f := goodFacts()
			f.EximSettings.Stdout = strings.Replace(eximSettings, "log_file_path = /var/log/exim_%slog", "log_file_path = "+raw, 1)
			if got := CheckHost(f); len(got) != 0 {
				t.Fatalf("monitored first file destination reported %+v", got)
			}
		})
	}
}

func TestCheckHostAcceptsEscapedLogDestination(t *testing.T) {
	f := goodFacts()
	f.MonitoredLog = "/var/log/example:exim_mainlog"
	f.EximSettings.Stdout = strings.Replace(eximSettings, "log_file_path = /var/log/exim_%slog", "log_file_path = syslog : /var/log/example::exim_%slog", 1)
	if got := CheckHost(f); len(got) != 0 {
		t.Fatalf("monitored destination containing a literal colon reported %+v", got)
	}
}

func TestCheckHostAcceptsSyslogDuplication(t *testing.T) {
	f := goodFacts()
	f.EximSettings.Stdout = strings.Replace(eximSettings, "log_file_path = /var/log/exim_%slog", "log_file_path = syslog : /var/log/exim_%slog", 1)
	if got := CheckHost(f); len(got) != 0 {
		t.Fatalf("syslog plus the main log reported %+v", got)
	}
}
