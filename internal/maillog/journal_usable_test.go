package maillog

import (
	"os"
	"path/filepath"
	"strings"
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
	prevDev, prevSock, prevDirs, prevSupported, prevMainCF, prevProc := devLogPath, journaldSocket, journalDirs, journalSupported, postfixMainCF, journalProcPath
	t.Cleanup(func() {
		devLogPath, journaldSocket, journalDirs, journalSupported, postfixMainCF, journalProcPath = prevDev, prevSock, prevDirs, prevSupported, prevMainCF, prevProc
	})
	devLogPath, journaldSocket, journalDirs = devLog, socket, []string{filepath.Join(root, "run", "log", "journal"), journals}
	journalSupported = func() bool { return supported }
	postfixMainCF = filepath.Join(root, "etc", "postfix", "main.cf")
	journalProcPath = filepath.Join(root, "proc")
	journalTestProcess(t, "1", "/usr/lib/systemd/systemd-journald", "0", "0::/system.slice/systemd-journald.service\n")
	journalTestProcess(t, "2", "/usr/libexec/postfix/master", "0", "0::/system.slice/postfix.service\n")
	if stored {
		if err := os.Symlink(filepath.Join(journals, "0123456789abcdef", "system.journal"), filepath.Join(journalProcPath, "1", "fd", "7")); err != nil {
			t.Fatal(err)
		}
	}
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

// Continued Postfix settings and failed reads must not hide postlogd logging.
func TestPostfixFileSelection(t *testing.T) {
	for _, tc := range []struct {
		name, config        string
		directory, wantFile bool
	}{
		{"continued value", "maillog_file =\n  /var/log/postfix.log\n", false, true},
		{"comment inside continuation", "maillog_file =\n# explanation\n  /var/log/postfix.log\n", false, true},
		{"last value wins", "maillog_file = /var/log/postfix.log\nmaillog_file =\n", false, false},
		{"continued unrelated value", "mydestination = example.net,\n maillog_file = /var/log/not-a-setting\n", false, false},
		{"unreadable configuration", "", true, true},
		{"scan failure", "#" + strings.Repeat("x", 70*1024) + "\nmaillog_file = /var/log/postfix.log\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usableJournalHost(t, true, true, true)
			if err := os.MkdirAll(filepath.Dir(postfixMainCF), 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.directory {
				if err := os.Mkdir(postfixMainCF, 0o755); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(postfixMainCF, []byte(tc.config), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "maillog")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			r, err := New(config.MailLogsConfig{Source: "auto", Units: []string{"postfix", "dovecot"}}, path, NewQueue())
			if err != nil {
				t.Fatal(err)
			}
			_, file := r.(*FileReader)
			if file != tc.wantFile {
				t.Fatalf("reader %T, want file %v", r, tc.wantFile)
			}
		})
	}
}

func journalTestProcess(t *testing.T, pid, exe, uid, cgroup string) {
	t.Helper()
	dir := filepath.Join(journalProcPath, pid)
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte("Uid:\t"+uid+"\t"+uid+"\t"+uid+"\t"+uid+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestJournalUsableRequiresLiveStorage(t *testing.T) {
	usableJournalHost(t, true, true, true)
	// Storage=none leaves old journal files but no open journal in journald.
	if err := os.Remove(filepath.Join(journalProcPath, "1", "fd", "7")); err != nil {
		t.Fatal(err)
	}
	if JournalUsable() {
		t.Fatal("old journal files counted as active storage")
	}
}

func TestAutoRequiresMailUnitCoverage(t *testing.T) {
	for _, tc := range []struct {
		name, cgroup string
		units        []string
		wantJournal  bool
	}{
		{"missing custom dovecot", "0::/system.slice/mail-imap.service\n", []string{"postfix", "dovecot"}, false},
		{"configured custom dovecot", "0::/system.slice/mail-imap.service\n", []string{"postfix", "mail-imap"}, true},
		{"missing postfix instance", "0::/system.slice/system-postfix.slice/postfix@secondary.service\n", []string{"postfix", "dovecot"}, false},
		{"configured instance", "0::/system.slice/system-postfix.slice/postfix@secondary.service\n", []string{"postfix", "postfix@secondary"}, true},
		{"legacy cgroup", "2:cpu:/\n1:name=systemd:/system.slice/mail-imap.service\n", []string{"postfix", "mail-imap"}, true},
		{"outside a service", "0::/user.slice/session-1.scope\n", []string{"postfix", "dovecot"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usableJournalHost(t, true, true, true)
			exe := "/usr/sbin/dovecot"
			if strings.Contains(tc.cgroup, "postfix@") {
				exe = "/usr/libexec/postfix/master"
			}
			journalTestProcess(t, "3", exe, "0", tc.cgroup)
			path := filepath.Join(t.TempDir(), "maillog")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			r, err := New(config.MailLogsConfig{Source: "auto", Units: tc.units}, path, NewQueue())
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

func TestAutoIgnoresUnprivilegedProcessNames(t *testing.T) {
	usableJournalHost(t, true, true, true)
	journalTestProcess(t, "3", "/tmp/dovecot", "1000", "0::/user.slice/session-1.scope\n")
	if !mailUnitsCovered([]string{"postfix"}) {
		t.Fatal("an unprivileged process forced file mode")
	}
}

// A mail master CSM cannot read keeps auto on the file. A process that is
// gone is another matter: see TestAutoSkipsVanishedMailProcess.
func TestAutoRejectsUnreadableMailProcess(t *testing.T) {
	usableJournalHost(t, true, true, true)
	journalTestProcess(t, "3", "/usr/sbin/dovecot", "0", "0::/system.slice/dovecot.service\n")
	status := filepath.Join(journalProcPath, "3", "status")
	if err := os.Remove(status); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(status, 0o755); err != nil {
		t.Fatal(err)
	}
	if mailUnitsCovered([]string{"postfix"}) {
		t.Fatal("an unreadable mail master was ignored")
	}
}

// Any user can start a short-lived process named master or dovecot. One
// that exits while CSM reads it must not decide the mail source, or anyone
// could keep mail on the file, where it only alerts.
func TestAutoSkipsVanishedMailProcess(t *testing.T) {
	usableJournalHost(t, true, true, true)
	journalTestProcess(t, "4", "/home/tenant/master", "0", "0::/user.slice/session-9.scope\n")
	if err := os.Remove(filepath.Join(journalProcPath, "4", "status")); err != nil {
		t.Fatal(err)
	}
	if !mailUnitsCovered([]string{"postfix"}) {
		t.Fatal("a process that exited mid-read kept auto on the file")
	}
	journalTestProcess(t, "5", "/home/tenant/dovecot", "0", "")
	if err := os.Remove(filepath.Join(journalProcPath, "5", "cgroup")); err != nil {
		t.Fatal(err)
	}
	if !mailUnitsCovered([]string{"postfix"}) {
		t.Fatal("a process whose cgroup vanished kept auto on the file")
	}
}

func TestAutoRecognizesReplacedMailExecutable(t *testing.T) {
	usableJournalHost(t, true, true, true)
	journalTestProcess(t, "3", "/usr/sbin/dovecot (deleted)", "0", "0::/system.slice/mail-imap.service\n")
	if mailUnitsCovered([]string{"postfix", "dovecot"}) {
		t.Fatal("an upgraded mail master's unit was ignored")
	}
}

func TestAutoRequiresPostfixSenderCoverage(t *testing.T) {
	usableJournalHost(t, true, true, true)
	journalTestProcess(t, "3", "/usr/libexec/postfix/master", "0", "0::/system.slice/mail-smtp.service\n")
	previous := lookupServiceUID
	t.Cleanup(func() { lookupServiceUID = previous })
	lookupServiceUID = func(string) (uint32, bool) { return 89, true }
	path := filepath.Join(t.TempDir(), "maillog")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := New(config.MailLogsConfig{Source: "auto", Units: []string{"postfix", "mail-smtp"}}, path, NewQueue())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(*FileReader); !ok {
		t.Fatalf("reader %T would discard non-root Postfix entries from the custom unit", r)
	}
}

func TestPostfixSecondaryInstanceFileLogging(t *testing.T) {
	for _, tc := range []struct {
		name, secondary   string
		missing, wantFile bool
	}{
		{"syslog", "", false, false},
		{"own log", "maillog_file = /var/log/postfix-secondary.log\n", false, true},
		{"unreadable", "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usableJournalHost(t, true, true, true)
			dir := filepath.Join(t.TempDir(), "postfix-secondary")
			if err := os.MkdirAll(filepath.Dir(postfixMainCF), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(postfixMainCF, []byte("multi_instance_directories =\n  "+dir+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if !tc.missing {
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "main.cf"), []byte(tc.secondary), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := postfixLogsToFile(); got != tc.wantFile {
				t.Fatalf("postfixLogsToFile=%v, want %v", got, tc.wantFile)
			}
		})
	}
}

// Any user controls their own executable's path and can make it unreadable,
// for example by nesting it deeper than PATH_MAX. Only root processes can be
// mail masters, so a user's process is skipped before its executable is
// read and cannot force mail onto the file.
func TestAutoIgnoresUnreadableUserExecutables(t *testing.T) {
	usableJournalHost(t, true, true, true)
	dir := filepath.Join(journalProcPath, "7")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A regular file where the exe link belongs: reading it fails with
	// EINVAL, an error that is not "the process is gone".
	if err := os.WriteFile(filepath.Join(dir, "exe"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte("Uid:\t1000\t1000\t1000\t1000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !mailUnitsCovered([]string{"postfix"}) {
		t.Fatal("a user's unreadable executable kept auto on the file")
	}
}

// CSM can start before Postfix and Dovecot. No mail master running yet is
// nothing the journal would miss: one that starts in a configured unit is
// read from its first entry.
func TestAutoPrefersJournalBeforeMailStarts(t *testing.T) {
	usableJournalHost(t, true, true, true)
	if err := os.RemoveAll(filepath.Join(journalProcPath, "2")); err != nil {
		t.Fatal(err)
	}
	if !mailUnitsCovered([]string{"postfix", "dovecot"}) {
		t.Fatal("no running mail master kept auto on the file")
	}
}
