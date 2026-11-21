package maillog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// usableJournalHost points the probe at a temporary tree: a syslog socket
// path that is or is not journald's, and stored journal files or none.
func usableJournalHost(t *testing.T, devLogToJournald, stored, supported bool) {
	t.Helper()
	root := t.TempDir()
	socket := filepath.Join(root, "run", "systemd", "journal", "dev-log")
	other := filepath.Join(root, "run", "rsyslog", "log")
	for _, p := range []string{socket, other} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	devLog := filepath.Join(root, "dev", "log")
	if err := os.MkdirAll(filepath.Dir(devLog), 0o755); err != nil {
		t.Fatal(err)
	}
	target := other
	if devLogToJournald {
		target = socket
	}
	if err := os.Symlink(target, devLog); err != nil {
		t.Fatal(err)
	}
	journals := filepath.Join(root, "var", "log", "journal")
	if err := os.MkdirAll(filepath.Join(journals, "0123456789abcdef"), 0o755); err != nil {
		t.Fatal(err)
	}
	if stored {
		if err := os.WriteFile(filepath.Join(journals, "0123456789abcdef", "system.journal"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prevDev, prevSock, prevDirs, prevSupported, prevMainCF := devLogPath, journaldSocket, journalDirs, journalSupported, postfixMainCF
	t.Cleanup(func() {
		devLogPath, journaldSocket, journalDirs, journalSupported, postfixMainCF = prevDev, prevSock, prevDirs, prevSupported, prevMainCF
	})
	devLogPath, journaldSocket, journalDirs = devLog, socket, []string{filepath.Join(root, "run", "log", "journal"), journals}
	journalSupported = func() bool { return supported }
	postfixMainCF = filepath.Join(root, "etc", "postfix", "main.cf")
}

// The journal holds every syslog line, with who sent it, only when syslog
// goes through journald and journald keeps what it receives.
func TestJournalUsable(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		toJournald, stored, built bool
		want                      bool
	}{
		{"journald owns syslog and stores", true, true, true, true},
		{"another daemon owns syslog", false, true, true, false},
		{"journald stores nothing", true, false, true, false},
		{"build without journal support", true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usableJournalHost(t, tc.toJournald, tc.stored, tc.built)
			if got := JournalUsable(); got != tc.want {
				t.Fatalf("JournalUsable = %v, want %v", got, tc.want)
			}
		})
	}
}

// auto reads the journal when it is usable, since only there can CSM tell a
// service's line from one any local user wrote; file and journal keep their
// meaning. Postfix writing its own log file keeps auto on that file.
func TestAutoPrefersUsableJournal(t *testing.T) {
	file := filepath.Join(t.TempDir(), "maillog")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	units := []string{"postfix", "dovecot"}
	for _, tc := range []struct {
		name        string
		source      string
		usable      bool
		postfixFile bool
		wantJournal bool
	}{
		{"auto with a usable journal", "auto", true, false, true},
		{"auto without one", "auto", false, false, false},
		{"auto when postfix writes its own file", "auto", true, true, false},
		{"file stays file", "file", true, false, false},
		{"journal stays journal", "journal", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usableJournalHost(t, tc.usable, tc.usable, true)
			if tc.postfixFile {
				if err := os.MkdirAll(filepath.Dir(postfixMainCF), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(postfixMainCF, []byte("# comment\nmaillog_file = /var/log/postfix.log\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			r, err := New(config.MailLogsConfig{Source: tc.source, Units: units}, file, NewQueue())
			if err != nil {
				t.Fatal(err)
			}
			_, journal := r.(*JournalReader)
			if journal != tc.wantJournal {
				t.Fatalf("reader %T, want journal %v", r, tc.wantJournal)
			}
		})
	}
}

// withJournalUnusable pins the probe to a host whose syslog does not go
// through journald, for tests about the file-first fallback.
func withJournalUnusable(t *testing.T) {
	t.Helper()
	prev := journalSupported
	t.Cleanup(func() { journalSupported = prev })
	journalSupported = func() bool { return false }
}
