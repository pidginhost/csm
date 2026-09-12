package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/store"
)

func TestHealthReportsWordPressVerificationCounts(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() { store.SetGlobal(prev); _ = db.Close() })
	paths := map[string]string{"/home/alice/a": "alice", "/home/alice/b": "alice", "/home/alice/c": "alice", "/home/alice/d": "alice", "/home/alice/e": "alice"}
	results := map[string]store.WPVerificationResult{"/home/alice/a": {State: "verified"}, "/home/alice/b": {State: "modified"}, "/home/alice/c": {State: "unverified"}, "/home/alice/d": {State: "not_wordpress"}}
	if err := db.UpdateWPVerification("core", time.Now(), "", paths, results, true); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: &config.Config{}}
	snap := health.Build(d, "test", nil)
	got := snap.WordPressVerification["core"]
	if got.Verified != 1 || got.Modified != 1 || got.Unverified != 1 || got.Unknown != 1 || got.NotWordPress != 1 {
		t.Fatalf("coverage counts conceal incomplete checks: %+v", got)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	snap = health.Build(d, "test", nil)
	if snap.WordPressVerification["core"].Error == "" {
		t.Fatal("unreadable coverage reported as zero failures")
	}
}
