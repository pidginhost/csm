package daemon

import (
	"testing"

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
