package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

func openTestDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "csm.bolt"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestMsgIndexPersister_RoundTrip(t *testing.T) {
	db := openTestDB(t)
	p := newMsgIndexPersister(db, 256, 50*time.Millisecond)
	p.Start()
	defer p.Stop()

	e := indexEntry{ScriptKey: "s:p", SourceIP: "192.0.2.1", CPUser: "u", At: time.Now()}
	p.Enqueue("id1", e)
	p.Flush() // synchronous flush for test determinism

	got, ok, err := p.Lookup("id1")
	if err != nil {
		t.Fatalf("Lookup err: %v", err)
	}
	if !ok || got.ScriptKey != "s:p" {
		t.Fatalf("Lookup = (%+v, %v)", got, ok)
	}
}

func TestMsgIndexPersister_OverflowDropsAndCounts(t *testing.T) {
	db := openTestDB(t)
	// Tiny queue so we can force overflow.
	p := newMsgIndexPersister(db, 1, time.Hour)
	p.Start()
	defer p.Stop()

	// Two enqueues without draining: second one must be dropped.
	p.Enqueue("a", indexEntry{At: time.Now()})
	p.Enqueue("b", indexEntry{At: time.Now()})

	if got := p.DroppedCount(); got == 0 {
		t.Errorf("expected drop count > 0, got %d", got)
	}
}

func TestMsgIndexPersister_SweepBolt(t *testing.T) {
	db := openTestDB(t)
	p := newMsgIndexPersister(db, 256, 50*time.Millisecond)
	p.Start()
	defer p.Stop()

	old := time.Now().Add(-26 * time.Hour)
	p.Enqueue("expired", indexEntry{At: old})
	p.Enqueue("fresh", indexEntry{At: time.Now()})
	p.Flush()

	swept, err := p.SweepBolt(time.Now().Add(-25 * time.Hour))
	if err != nil {
		t.Fatalf("SweepBolt: %v", err)
	}
	if swept != 1 {
		t.Errorf("swept = %d, want 1", swept)
	}
	if _, ok, _ := p.Lookup("expired"); ok {
		t.Errorf("expired entry must be removed")
	}
	if _, ok, _ := p.Lookup("fresh"); !ok {
		t.Errorf("fresh entry must remain")
	}
}
