package store

import (
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestSpamSourcesRoundTrip(t *testing.T) {
	db := openTestDB(t)

	empty, err := db.LoadSpamSources()
	if err != nil {
		t.Fatalf("LoadSpamSources before save: %v", err)
	}
	if empty == nil || len(empty) != 0 {
		t.Fatalf("LoadSpamSources before save = %v, want an empty non-nil map", empty)
	}

	t1 := time.Date(2026, 10, 30, 8, 15, 0, 123456789, time.UTC)
	t2 := time.Date(2026, 10, 31, 9, 30, 5, 0, time.UTC)
	clean := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	finding := time.Date(2026, 10, 31, 9, 30, 6, 0, time.UTC)
	seen4 := time.Date(2026, 10, 31, 9, 30, 7, 0, time.UTC)
	seen6 := time.Date(2026, 10, 29, 23, 59, 59, 999999999, time.UTC)
	want := map[string]SpamSource{
		"198.51.100.7": {Occasions: []time.Time{t1, t2}, LastClean: clean, LastFinding: finding, Seen: seen4},
		"2001:db8::7":  {Seen: seen6},
	}
	if saveErr := db.SaveSpamSources(want); saveErr != nil {
		t.Fatalf("SaveSpamSources: %v", saveErr)
	}

	var raw string
	if viewErr := db.bolt.View(func(tx *bolt.Tx) error {
		raw = string(tx.Bucket([]byte(spamSourceBucket)).Get([]byte("2001:db8::7")))
		return nil
	}); viewErr != nil {
		t.Fatalf("reading stored IPv6 entry: %v", viewErr)
	}
	if wantRaw := `{"seen":"2026-10-29T23:59:59.999999999Z"}`; raw != wantRaw {
		t.Errorf("stored IPv6 entry = %s, want %s", raw, wantRaw)
	}

	got, err := db.LoadSpamSources()
	if err != nil {
		t.Fatalf("LoadSpamSources: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("loaded %d IPs, want 2: %v", len(got), got)
	}

	v4, ok := got["198.51.100.7"]
	if !ok {
		t.Fatalf("IPv4 entry missing: %v", got)
	}
	if len(v4.Occasions) != 2 || !v4.Occasions[0].Equal(t1) || !v4.Occasions[1].Equal(t2) {
		t.Errorf("IPv4 Occasions = %v, want [%v %v] in that order", v4.Occasions, t1, t2)
	}
	if !v4.LastClean.Equal(clean) {
		t.Errorf("IPv4 LastClean = %v, want %v", v4.LastClean, clean)
	}
	if !v4.LastFinding.Equal(finding) {
		t.Errorf("IPv4 LastFinding = %v, want %v", v4.LastFinding, finding)
	}
	if !v4.Seen.Equal(seen4) {
		t.Errorf("IPv4 Seen = %v, want %v", v4.Seen, seen4)
	}

	v6, ok := got["2001:db8::7"]
	if !ok {
		t.Fatalf("IPv6 entry missing: %v", got)
	}
	if len(v6.Occasions) != 0 {
		t.Errorf("IPv6 Occasions = %v, want none", v6.Occasions)
	}
	if !v6.LastClean.IsZero() || !v6.LastFinding.IsZero() {
		t.Errorf("IPv6 LastClean = %v, LastFinding = %v, want both zero", v6.LastClean, v6.LastFinding)
	}
	if !v6.Seen.Equal(seen6) {
		t.Errorf("IPv6 Seen = %v, want %v", v6.Seen, seen6)
	}
}

func TestSaveSpamSourcesDropsMissingIPs(t *testing.T) {
	db := openTestDB(t)

	seen := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
	if err := db.SaveSpamSources(map[string]SpamSource{
		"198.51.100.7": {Seen: seen},
		"198.51.100.8": {Seen: seen},
	}); err != nil {
		t.Fatalf("SaveSpamSources initial: %v", err)
	}
	later := seen.Add(10 * time.Minute)
	if err := db.SaveSpamSources(map[string]SpamSource{
		"198.51.100.8": {Seen: later},
	}); err != nil {
		t.Fatalf("SaveSpamSources replacement: %v", err)
	}

	got, err := db.LoadSpamSources()
	if err != nil {
		t.Fatalf("LoadSpamSources: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("loaded %d IPs, want 1: %v", len(got), got)
	}
	if _, ok := got["198.51.100.7"]; ok {
		t.Errorf("IP dropped from the tracker survived the next save")
	}
	if !got["198.51.100.8"].Seen.Equal(later) {
		t.Errorf("198.51.100.8 Seen = %v, want the newer %v", got["198.51.100.8"].Seen, later)
	}

	if err = db.SaveSpamSources(nil); err != nil {
		t.Fatalf("SaveSpamSources empty: %v", err)
	}
	got, err = db.LoadSpamSources()
	if err != nil {
		t.Fatalf("LoadSpamSources after empty save: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty save left %d IPs: %v", len(got), got)
	}
}

func TestSaveSpamSourcesSkipsEmptyKey(t *testing.T) {
	db := openTestDB(t)

	seen := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
	if err := db.SaveSpamSources(map[string]SpamSource{
		"":             {Seen: seen},
		"198.51.100.7": {Seen: seen},
	}); err != nil {
		t.Fatalf("SaveSpamSources with an empty key: %v", err)
	}

	got, err := db.LoadSpamSources()
	if err != nil {
		t.Fatalf("LoadSpamSources: %v", err)
	}
	if len(got) != 1 || !got["198.51.100.7"].Seen.Equal(seen) {
		t.Errorf("loaded %v, want only 198.51.100.7 seen at %v", got, seen)
	}
}

func TestLoadSpamSourcesSkipsCorruptEntries(t *testing.T) {
	db := openTestDB(t)

	seen := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
	if err := db.SaveSpamSources(map[string]SpamSource{
		"198.51.100.7": {Seen: seen},
	}); err != nil {
		t.Fatalf("SaveSpamSources: %v", err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(spamSourceBucket)).Put([]byte("198.51.100.9"), []byte("{not json"))
	}); err != nil {
		t.Fatalf("writing corrupt entry: %v", err)
	}

	got, err := db.LoadSpamSources()
	if err != nil {
		t.Fatalf("LoadSpamSources: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("loaded %d IPs, want 1: %v", len(got), got)
	}
	if !got["198.51.100.7"].Seen.Equal(seen) {
		t.Errorf("198.51.100.7 Seen = %v, want %v", got["198.51.100.7"].Seen, seen)
	}
}

func TestLoadSpamSourcesSkipsMissingState(t *testing.T) {
	for _, raw := range []string{"null", "{}", `{"last_clean":"2026-10-31T10:00:00Z"}`} {
		t.Run(raw, func(t *testing.T) {
			db := openTestDB(t)
			seen := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
			if err := db.SaveSpamSources(map[string]SpamSource{
				"198.51.100.7": {Seen: seen},
			}); err != nil {
				t.Fatalf("SaveSpamSources: %v", err)
			}
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte(spamSourceBucket)).Put([]byte("198.51.100.9"), []byte(raw))
			}); err != nil {
				t.Fatal(err)
			}

			got, err := db.LoadSpamSources()
			if err != nil {
				t.Fatalf("LoadSpamSources: %v", err)
			}
			if len(got) != 1 || !got["198.51.100.7"].Seen.Equal(seen) {
				t.Errorf("loaded %v, want only 198.51.100.7 seen at %v", got, seen)
			}
		})
	}
}
