package store

import (
	"testing"
	"time"
)

// An external script host in wp_options that shows no attacker marker is
// invisible to the structural classifier. The store remembers every
// (site, option, host) it has seen: the first scan of a site records its
// hosts silently as the baseline, and only a host that appears later is
// reported as new, once.
func TestExternalScriptHostFirstSeenAfterBaseline(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	now := time.Date(2026, 9, 2, 8, 0, 0, 0, time.UTC)
	const site = "alice_wp|wp_"

	isNew, err := db.MarkExternalScriptSeen(site, "widget_text", "cdn.vendor.example", now)
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Fatal("first scan of a site must record hosts silently, not report them")
	}
	if err = db.FinishExternalScriptBaseline(site, now); err != nil {
		t.Fatal(err)
	}

	isNew, err = db.MarkExternalScriptSeen(site, "widget_text", "cdn.vendor.example", now.Add(time.Hour))
	if err != nil || isNew {
		t.Fatalf("baseline host reported as new: new=%v err=%v", isNew, err)
	}
	isNew, err = db.MarkExternalScriptSeen(site, "widget_text", "loader.attacker.example", now.Add(time.Hour))
	if err != nil || !isNew {
		t.Fatalf("host appearing after the baseline not reported: new=%v err=%v", isNew, err)
	}
	isNew, err = db.MarkExternalScriptSeen(site, "widget_text", "loader.attacker.example", now.Add(2*time.Hour))
	if err != nil || isNew {
		t.Fatalf("already-reported host reported again: new=%v err=%v", isNew, err)
	}

	// Another site starts its own silent baseline.
	isNew, err = db.MarkExternalScriptSeen("bob_wp|wp_", "widget_text", "loader.attacker.example", now.Add(2*time.Hour))
	if err != nil || isNew {
		t.Fatalf("baseline of a second site reported a host: new=%v err=%v", isNew, err)
	}
}
