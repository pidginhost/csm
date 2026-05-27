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

func TestSaveIncidentRoundTripsCompoundFlags(t *testing.T) {
	db := newTestStore(t)
	want := sampleIncident("inc_flags")
	want.CompoundFlags = incident.CompoundFlags{Webshell: true}
	if err := db.SaveIncident(want); err != nil {
		t.Fatal(err)
	}
	got, _, err := db.GetIncident("inc_flags")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.CompoundFlags.Webshell || got.CompoundFlags.C2 {
		t.Errorf("CompoundFlags = %+v, want webshell only", got.CompoundFlags)
	}
}

func TestListIncidentsByStatusFilters(t *testing.T) {
	db := newTestStore(t)
	a := sampleIncident("inc_a")
	a.Status = incident.StatusOpen
	b := sampleIncident("inc_b")
	b.Status = incident.StatusResolved
	c := sampleIncident("inc_c")
	c.Status = incident.StatusOpen
	for _, inc := range []incident.Incident{a, b, c} {
		if err := db.SaveIncident(inc); err != nil {
			t.Fatal(err)
		}
	}
	open, err := db.ListIncidentsByStatus(incident.StatusOpen)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 2 {
		t.Errorf("open count: want 2, got %d", len(open))
	}
}

func TestCompactIncidentsPrunesOldResolved(t *testing.T) {
	db := newTestStore(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	stale := sampleIncident("inc_stale")
	stale.Status = incident.StatusResolved
	stale.UpdatedAt = now.Add(-31 * 24 * time.Hour)

	fresh := sampleIncident("inc_fresh")
	fresh.Status = incident.StatusResolved
	fresh.UpdatedAt = now.Add(-29 * 24 * time.Hour)

	openOld := sampleIncident("inc_open_old")
	openOld.Status = incident.StatusOpen
	openOld.UpdatedAt = now.Add(-90 * 24 * time.Hour)

	for _, inc := range []incident.Incident{stale, fresh, openOld} {
		if err := db.SaveIncident(inc); err != nil {
			t.Fatal(err)
		}
	}

	pruned, err := db.CompactIncidents(now, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	if pruned != 1 {
		t.Errorf("pruned: want 1 (only inc_stale), got %d", pruned)
	}

	if _, ok, _ := db.GetIncident("inc_stale"); ok {
		t.Errorf("inc_stale should be gone")
	}
	if _, ok, _ := db.GetIncident("inc_fresh"); !ok {
		t.Errorf("inc_fresh (29 days old) must survive")
	}
	if _, ok, _ := db.GetIncident("inc_open_old"); !ok {
		t.Errorf("inc_open_old (open status) must survive any age")
	}
}
