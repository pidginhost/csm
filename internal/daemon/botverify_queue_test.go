package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

func TestBotVerificationQueuePublishedAtStartup(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := New(&config.Config{}, nil, nil, "")
	t.Cleanup(func() {
		close(d.stopCh)
		d.wg.Wait()
		checks.SetBotVerifier(nil, nil)
		_ = db.Close()
	})
	d.startBotVerifier(db, nil)
	got, exists := d.QueueStatuses()["bot_verification.requests"]
	if !exists || got.Capacity != 256 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" {
		t.Fatalf("published verifier has no queue health: exists=%v status=%+v", exists, got)
	}
}

func TestBotVerifierHonorsStoredNoPTRRecords(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := New(&config.Config{}, nil, nil, "")
	t.Cleanup(func() {
		close(d.stopCh)
		d.wg.Wait()
		checks.SetBotVerifier(nil, nil)
		_ = db.Close()
	})
	ip := net.ParseIP("192.0.2.40")
	if err := db.PutBotVerifyUnverifiable(ip, "facebookbot", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	d.startBotVerifier(db, nil)
	// A record written before this start came from the previous process, so
	// the new verifier must read it instead of repeating the lookup.
	if d.botVerifier.Enqueue(ip, "facebookbot") {
		t.Fatal("daemon verifier queued DNS for a source with a stored no-PTR record")
	}
	if !d.botVerifier.Enqueue(net.ParseIP("192.0.2.41"), "facebookbot") {
		t.Fatal("daemon verifier refused a source without a record")
	}
}
