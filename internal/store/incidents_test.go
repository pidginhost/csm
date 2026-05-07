package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/incident"
)

func newTestStore(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "csm.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func sampleIncident(id string) incident.Incident {
	return incident.Incident{
		ID:        id,
		Kind:      incident.KindWebAccountCompromise,
		Status:    incident.StatusOpen,
		Severity:  alert.High,
		Account:   "alice",
		CreatedAt: time.Unix(1_700_000_000, 0).UTC(),
		UpdatedAt: time.Unix(1_700_000_000, 0).UTC(),
	}
}

func TestSaveAndGetIncident(t *testing.T) {
	db := newTestStore(t)
	want := sampleIncident("inc_a")
	if err := db.SaveIncident(want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, ok, err := db.GetIncident("inc_a")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !ok {
		t.Fatal("expected found")
	}
	if got.ID != want.ID || got.Account != want.Account || got.Severity != want.Severity {
		t.Errorf("incident: %+v", got)
	}
}

func TestGetIncidentMissReturnsFalseNoError(t *testing.T) {
	db := newTestStore(t)
	_, ok, err := db.GetIncident("inc_missing")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Errorf("expected miss")
	}
}

func TestListIncidentsReturnsAllSortedByUpdatedAtDesc(t *testing.T) {
	db := newTestStore(t)
	a := sampleIncident("inc_a")
	a.UpdatedAt = time.Unix(1_700_000_000, 0).UTC()
	b := sampleIncident("inc_b")
	b.UpdatedAt = time.Unix(1_700_000_300, 0).UTC()
	if err := db.SaveIncident(a); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveIncident(b); err != nil {
		t.Fatal(err)
	}
	list, err := db.ListIncidents()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("len: %d", len(list))
	}
	if list[0].ID != "inc_b" {
		t.Errorf("expected newest first; got %s then %s", list[0].ID, list[1].ID)
	}
}

func TestSaveIncidentRoundTripsTimeline(t *testing.T) {
	db := newTestStore(t)
	want := sampleIncident("inc_c")
	want.Timeline = []incident.IncidentEvent{
		{Time: time.Unix(1_700_000_000, 0).UTC(), Kind: "finding", Check: "wp_login_bruteforce", Message: "burst"},
	}
	if err := db.SaveIncident(want); err != nil {
		t.Fatal(err)
	}
	got, _, _ := db.GetIncident("inc_c")
	if len(got.Timeline) != 1 || got.Timeline[0].Check != "wp_login_bruteforce" {
		t.Errorf("Timeline lost or mangled: %+v", got.Timeline)
	}
}
