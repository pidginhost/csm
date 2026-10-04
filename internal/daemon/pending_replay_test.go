package daemon

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// A finding still queued at shutdown used to be written to history only.
// For realtime-only checks nothing re-detects it after a restart, so the
// auto-response it should have triggered was lost for good. The batch is now
// parked and replayed through the full dispatch pipeline at the next start.
func TestPendingFindingsAtShutdownAreDispatchedAtNextStart(t *testing.T) {
	dir := t.TempDir()
	_, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	stopping := New(&config.Config{StatePath: dir}, st, nil, "")
	stopping.persistPendingFindingsOnShutdown([]alert.Finding{{
		Severity:  alert.Critical,
		Check:     "webshell_realtime",
		FilePath:  "/home/acct/public_html/shell.php",
		Message:   "webshell written at shutdown",
		Timestamp: time.Now(),
	}})

	previousHook := alert.CentralHook
	var dispatched atomic.Int64
	alert.SetCentralHook(func(alert.Finding) { dispatched.Add(1) })
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })

	reopened, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	starting := New(&config.Config{StatePath: dir}, reopened, nil, "")
	starting.replayPendingFindings()

	if n := dispatched.Load(); n != 1 {
		t.Fatalf("dispatched %d findings from the parked shutdown batch, want 1", n)
	}
	left, err := reopened.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("%d findings still parked after replay", len(left))
	}
}

func TestPendingReplayDropsRetiredThreatScore(t *testing.T) {
	dir := t.TempDir()
	_, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cause := alert.Cause{Check: "db_siteurl_hijack", FindingID: "0123456789abcdef"}
	if err := st.AppendPendingFindings([]alert.Finding{
		{Check: "local_threat_score", Severity: alert.Critical, SourceIP: "192.0.2.10", Message: "legacy score", Timestamp: time.Now()},
		{Check: "local_threat_score", Severity: alert.Critical, SourceIP: "192.0.2.12", Message: "database session", Cause: &cause, Timestamp: time.Now()},
		{Check: "fixture", Severity: alert.High, Message: "unrelated", Timestamp: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	previousHook := alert.CentralHook
	var dispatched []alert.Finding
	alert.SetCentralHook(func(f alert.Finding) { dispatched = append(dispatched, f) })
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })
	d := New(&config.Config{StatePath: dir}, st, nil, "")
	d.replayPendingFindings()
	if len(dispatched) != 2 || dispatched[0].SourceIP != "192.0.2.12" || dispatched[0].Cause == nil || *dispatched[0].Cause != cause || dispatched[1].Check != "fixture" {
		t.Fatalf("dispatched = %+v, want the database session and unrelated finding", dispatched)
	}
	if left, err := st.TakePendingFindings(); err != nil || len(left) != 0 {
		t.Fatalf("pending findings = %+v, error %v", left, err)
	}
}
