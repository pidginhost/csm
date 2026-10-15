package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// An applied admission block records its threat row until the block's
// absolute expiry. Its consumer can see the same block twice, so a repeat
// leaves the stored row exactly as it was; a shorter expiry never
// truncates a live row and a past one writes nothing.
func TestThreatDBAddTemporaryUntilIsIdempotent(t *testing.T) {
	withTestThreatStore(t)
	db := newTestThreatDB(t)
	expires := time.Now().Add(2 * time.Hour)
	if err := db.AddTemporaryUntil("192.0.2.70", "CSM auto-block: ssh_brute", expires); err != nil {
		t.Fatal(err)
	}
	match, ok := db.LookupMatch("192.0.2.70")
	if !ok || match.Source != "CSM auto-block: ssh_brute" || !match.ExpiresAt.Equal(expires) || match.Permanent {
		t.Fatalf("LookupMatch = %+v, %t; want the block's own expiry %v", match, ok, expires)
	}
	first, found := store.Global().GetPermanentBlock("192.0.2.70")
	if !found || first.Source != store.ThreatSourceAutoBlock || !first.ExpiresAt.Equal(expires) {
		t.Fatalf("stored row = %+v, %t", first, found)
	}
	time.Sleep(2 * time.Millisecond)
	if err := db.AddTemporaryUntil("192.0.2.70", "CSM auto-block: ssh_brute", expires); err != nil {
		t.Fatal(err)
	}
	if err := db.AddTemporaryUntil("192.0.2.70", "CSM auto-block: ssh_brute", expires.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if again, _ := store.Global().GetPermanentBlock("192.0.2.70"); again != first {
		t.Fatalf("a repeated block rewrote its row: %+v, was %+v", again, first)
	}
	if match, _ = db.LookupMatch("192.0.2.70"); !match.ExpiresAt.Equal(expires) {
		t.Fatalf("a shorter expiry truncated the live row: %v", match.ExpiresAt)
	}
	if err := db.AddTemporaryUntil("192.0.2.71", "CSM auto-block: ssh_brute", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok = db.LookupMatch("192.0.2.71"); ok {
		t.Fatal("an expired block recorded threat evidence")
	}
	if _, found = store.Global().GetPermanentBlock("192.0.2.71"); found {
		t.Fatal("an expired block was stored")
	}
}

func TestThreatDBAddTemporaryUntilRetriesFailedStore(t *testing.T) {
	withTestThreatStore(t)
	working := store.Global()
	closed, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = closed.Close(); err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(closed)
	t.Cleanup(func() { store.SetGlobal(working) })
	db := newTestThreatDB(t)
	expires := time.Now().Add(time.Hour)
	if err = db.AddTemporaryUntil("192.0.2.72", "CSM auto-block: ssh_brute", expires); err == nil {
		t.Fatal("a failed store write reported success")
	}
	if _, ok := db.LookupMatch("192.0.2.72"); ok {
		t.Fatal("failed persistence published threat evidence")
	}
	store.SetGlobal(working)
	if err = db.AddTemporaryUntil("192.0.2.72", "CSM auto-block: ssh_brute", expires); err != nil {
		t.Fatal(err)
	}
	if row, ok := working.GetPermanentBlock("192.0.2.72"); !ok || !row.ExpiresAt.Equal(expires) {
		t.Fatalf("retry did not persist the row: %+v, %t", row, ok)
	}
	// Startup uses a generic label; replay must preserve that view and
	// the persisted timestamp, not treat the label as a new block.
	reloaded := newTestThreatDB(t)
	reloaded.loadPermanentBlocklist()
	before, _ := reloaded.LookupMatch("192.0.2.72")
	if err = reloaded.AddTemporaryUntil("192.0.2.72", "CSM auto-block: ssh_brute", expires); err != nil {
		t.Fatal(err)
	}
	if after, _ := reloaded.LookupMatch("192.0.2.72"); after != before {
		t.Fatalf("replay changed the reloaded view: %+v -> %+v", before, after)
	}
}

// A held write must not stop reputation lookups or whitelist reload. A
// concurrent removal must run after publication, so it cannot be undone
// by the older batch finishing later.
func TestThreatDBAddTemporaryUntilDoesNotHoldLookupLock(t *testing.T) {
	withTestThreatStore(t)
	db := newTestThreatDB(t)
	const ip = "192.0.2.75"
	db.AddTemporary(ip, "prior", time.Hour)
	entered, release := make(chan struct{}), make(chan struct{})
	previous := persistAppliedThreats
	persistAppliedThreats = func(sdb *store.DB, entries []store.PermanentBlockEntry) error {
		close(entered)
		<-release
		return previous(sdb, entries)
	}
	done := make(chan error, 1)
	go func() { done <- db.AddTemporaryUntil(ip, "new", time.Now().Add(2*time.Hour)) }()
	<-entered
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
		if err := <-done; err != nil {
			t.Errorf("applied write failed: %v", err)
		}
		persistAppliedThreats = previous
	})
	read := make(chan ThreatMatch, 1)
	go func() { m, _ := db.LookupMatch(ip); read <- m }()
	select {
	case m := <-read:
		if m.Source != "prior" {
			t.Errorf("uncommitted batch became visible: %+v", m)
		}
	case <-time.After(5 * time.Second):
		t.Error("lookup waited for the durable write")
	}
	reloaded := make(chan struct{})
	go func() { db.SetConfigWhitelist([]string{"192.0.2.76"}); close(reloaded) }()
	select {
	case <-reloaded:
	case <-time.After(5 * time.Second):
		t.Error("config reload waited for the durable write")
	}
	removed := make(chan struct{})
	go func() { db.RemoveTemporary(ip); close(removed) }()
	select {
	case <-removed:
		t.Error("removal passed an uncommitted threat writer")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	released = true
	// Cleanup also joins the writer before restoring its hook.
	<-reloaded
	<-removed
	if _, ok := db.LookupMatch(ip); ok {
		t.Error("the older batch restored removed memory")
	}
	if !db.IsConfigWhitelisted("192.0.2.76") {
		t.Error("concurrent reload was lost")
	}
}
