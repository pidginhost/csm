package health

import (
	"encoding/json"
	"testing"
	"time"
)

// The snapshot carries the correlation attribution block as the provider
// reports it, copies its maps, and omits it entirely when the daemon has
// nothing to say (older daemons, or before the first merge).
func TestBuild_CarriesCorrelationAttribution(t *testing.T) {
	since := time.Date(2026, 9, 9, 8, 0, 0, 0, time.UTC)
	p := &fakeProvider{
		hostname: "test.host",
		started:  time.Now().Add(-time.Hour),
		watchers: map[string]bool{"fanotify": true},
		storeOK:  true,
		attribution: &CorrelationAttribution{
			Current:          map[string]int{"db_rogue_admin": 2},
			Cumulative:       map[string]int{"db_rogue_admin": 7, "webshell": 1},
			ActiveSetUpdates: 3,
			Since:            since,
		},
	}
	snap := Build(p, "1.0", nil)
	got := snap.CorrelationAttribution
	if got == nil || got.Current["db_rogue_admin"] != 2 || got.Cumulative["webshell"] != 1 || got.ActiveSetUpdates != 3 || !got.Since.Equal(since) {
		t.Fatalf("correlation attribution = %+v", got)
	}
	got.Current["db_rogue_admin"] = 99
	if p.attribution.Current["db_rogue_admin"] != 2 {
		t.Fatal("snapshot shares the provider's map")
	}

	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["correlation_attribution"]; !ok {
		t.Fatalf("snapshot JSON lacks correlation_attribution: %s", raw)
	}

	p.attribution = nil
	raw, err = json.Marshal(Build(p, "1.0", nil))
	if err != nil {
		t.Fatal(err)
	}
	// Unmarshal merges into an existing map, so start from an empty one.
	decoded = map[string]json.RawMessage{}
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["correlation_attribution"]; ok {
		t.Fatalf("absent attribution must be omitted from JSON: %s", raw)
	}
}
