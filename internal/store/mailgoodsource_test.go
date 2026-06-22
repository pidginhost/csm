package store

import (
	"testing"
	"time"
)

func TestMailGoodSourceRoundTrip(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now().Truncate(time.Second)
	data := map[string]map[string]GoodSourcePair{
		"198.51.100.10": {
			"a@example.ro": {First: now.Add(-2 * time.Hour), Last: now.Add(-1 * time.Minute)},
			"b@example.ro": {First: now.Add(-3 * time.Hour), Last: now.Add(-2 * time.Minute)},
		},
		"198.51.100.11": {
			"c@example.ro": {First: now.Add(-1 * time.Hour), Last: now},
		},
	}
	if saveErr := db.SaveMailGoodSource(data); saveErr != nil {
		t.Fatalf("SaveMailGoodSource: %v", saveErr)
	}

	got, loadErr := db.LoadMailGoodSource()
	if loadErr != nil {
		t.Fatalf("LoadMailGoodSource: %v", loadErr)
	}
	if len(got) != 2 {
		t.Fatalf("loaded %d IPs, want 2", len(got))
	}
	if !got["198.51.100.10"]["a@example.ro"].First.Equal(data["198.51.100.10"]["a@example.ro"].First) {
		t.Errorf("First mismatch for a@example.ro")
	}
	if !got["198.51.100.11"]["c@example.ro"].Last.Equal(now) {
		t.Errorf("Last mismatch for c@example.ro")
	}
}

func TestMailGoodSourceSaveReplacesPrevious(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now().Truncate(time.Second)
	if saveErr := db.SaveMailGoodSource(map[string]map[string]GoodSourcePair{
		"198.51.100.10": {"a@example.ro": {First: now, Last: now}},
	}); saveErr != nil {
		t.Fatalf("SaveMailGoodSource initial: %v", saveErr)
	}
	if saveErr := db.SaveMailGoodSource(map[string]map[string]GoodSourcePair{
		"198.51.100.20": {"x@example.ro": {First: now, Last: now}},
	}); saveErr != nil {
		t.Fatalf("SaveMailGoodSource replacement: %v", saveErr)
	}

	got, loadErr := db.LoadMailGoodSource()
	if loadErr != nil {
		t.Fatalf("LoadMailGoodSource: %v", loadErr)
	}
	if _, ok := got["198.51.100.10"]; ok {
		t.Errorf("stale IP must be replaced by snapshot save")
	}
	if _, ok := got["198.51.100.20"]; !ok {
		t.Errorf("new IP missing after replace")
	}
}

func TestMailGoodSourceSaveEmptyClearsPrevious(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now().Truncate(time.Second)
	if saveErr := db.SaveMailGoodSource(map[string]map[string]GoodSourcePair{
		"198.51.100.10": {"a@example.ro": {First: now, Last: now}},
	}); saveErr != nil {
		t.Fatalf("SaveMailGoodSource initial: %v", saveErr)
	}
	if saveErr := db.SaveMailGoodSource(nil); saveErr != nil {
		t.Fatalf("SaveMailGoodSource empty: %v", saveErr)
	}
	got, loadErr := db.LoadMailGoodSource()
	if loadErr != nil {
		t.Fatalf("LoadMailGoodSource: %v", loadErr)
	}
	if len(got) != 0 {
		t.Fatalf("empty snapshot should clear previous records, got %d", len(got))
	}
}

func TestMailGoodSourceLoadEmpty(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	got, loadErr := db.LoadMailGoodSource()
	if loadErr != nil {
		t.Fatalf("LoadMailGoodSource: %v", loadErr)
	}
	if len(got) != 0 {
		t.Errorf("empty load should return empty map, got %d", len(got))
	}
}

func TestMailGoodSourceLoadClosedReturnsError(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := db.LoadMailGoodSource(); err == nil {
		t.Fatalf("LoadMailGoodSource on closed store returned nil error")
	}
}
