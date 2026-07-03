package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

// TestDropAutoBlockThreatRowClearsAutoBlockOnly pins STO-18 on the daemon
// side: an operator unblock (CLI `csm firewall remove`) must drop the
// auto-block threat row for the IP so ip_reputation stops re-flagging it,
// while an operator permanent block survives the firewall-only unblock.
func TestDropAutoBlockThreatRowClearsAutoBlockOnly(t *testing.T) {
	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { store.SetGlobal(nil); _ = sdb.Close() })
	store.SetGlobal(sdb)
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))

	tdb := checks.GetThreatDB()
	tdb.AddTemporary("192.0.2.10", "web_attack", time.Hour)
	// Operator permanent block.
	tdb.AddPermanent("192.0.2.12", "operator block")

	// Sanity: both flag before the unblock.
	if _, ok := tdb.Lookup("192.0.2.10"); !ok {
		t.Fatal("auto-block IP should flag before unblock")
	}
	if _, ok := tdb.Lookup("192.0.2.12"); !ok {
		t.Fatal("operator IP should flag before unblock")
	}

	dropAutoBlockThreatRow("192.0.2.10")

	if src, ok := tdb.Lookup("192.0.2.10"); ok {
		t.Fatalf("auto-block IP still flagged after unblock: source=%q", src)
	}
	if _, found := sdb.GetPermanentBlock("192.0.2.10"); found {
		t.Fatal("auto-block threat row survived unblock in store")
	}

	// Unblocking an operator-blocked IP must not clear its permanent row.
	dropAutoBlockThreatRow("192.0.2.12")
	if _, ok := tdb.Lookup("192.0.2.12"); !ok {
		t.Fatal("operator IP unflagged by unblock")
	}
	entry, found := sdb.GetPermanentBlock("192.0.2.12")
	if !found || entry.Source != store.ThreatSourceOperator {
		t.Fatalf("operator threat row not intact: found=%v entry=%+v", found, entry)
	}
}

func TestDropAutoBlockThreatRowWithoutStoreClearsTemporaryOnly(t *testing.T) {
	prevStore := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(prevStore) })
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))

	tdb := checks.GetThreatDB()
	tdb.AddTemporary("192.0.2.20", "web_attack", time.Hour)
	tdb.AddPermanent("192.0.2.21", "operator block")

	dropAutoBlockThreatRow("192.0.2.20")
	if src, ok := tdb.Lookup("192.0.2.20"); ok {
		t.Fatalf("temporary threat survived storeless unblock: source=%q", src)
	}

	dropAutoBlockThreatRow("192.0.2.21")
	if _, ok := tdb.Lookup("192.0.2.21"); !ok {
		t.Fatal("operator threat was removed by storeless unblock")
	}
}
