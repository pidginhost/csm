package store

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

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

func putRawIncidentRow(t *testing.T, db *DB, id string, raw []byte) {
	t.Helper()
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(incidentsBucket)).Put([]byte(id), raw)
	})
	if err != nil {
		t.Fatalf("put raw incident row %q: %v", id, err)
	}
}

func mustMarshalIncident(t *testing.T, inc incident.Incident) []byte {
	t.Helper()
	raw, err := json.Marshal(inc)
	if err != nil {
		t.Fatalf("marshal incident: %v", err)
	}
	return raw
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

func TestGetIncidentCorruptRecordReturnsErrorWithoutFound(t *testing.T) {
	db := newTestStore(t)
	putRawIncidentRow(t, db, "inc_corrupt", []byte("{bad"))

	got, ok, err := db.GetIncident("inc_corrupt")
	if err == nil {
		t.Fatal("expected error for corrupt incident row")
	}
	if ok {
		t.Fatalf("found = true with error; got incident %+v", got)
	}
}

func TestGetIncidentInvalidStoredRecordReturnsErrorWithoutFound(t *testing.T) {
	db := newTestStore(t)
	bad := sampleIncident("inc_value_id")
	putRawIncidentRow(t, db, "inc_key_id", mustMarshalIncident(t, bad))

	got, ok, err := db.GetIncident("inc_key_id")
	if err == nil {
		t.Fatal("expected error for invalid incident row")
	}
	if ok {
		t.Fatalf("found = true with error; got incident %+v", got)
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

// A single corrupt JSON row must not block restore of every other
// incident at startup.
func TestListIncidentsSkipsCorruptRecord(t *testing.T) {
	db := newTestStore(t)

	good1 := sampleIncident("inc_good1")
	good2 := sampleIncident("inc_good2")
	if err := db.SaveIncident(good1); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveIncident(good2); err != nil {
		t.Fatal(err)
	}

	putRawIncidentRow(t, db, "inc_corrupt", []byte("not-json{"))

	list, err := db.ListIncidents()
	if err != nil {
		t.Fatalf("ListIncidents must not fail on a single corrupt row: %v", err)
	}
	gotIDs := make([]string, 0, len(list))
	for _, inc := range list {
		gotIDs = append(gotIDs, inc.ID)
	}
	sort.Strings(gotIDs)
	if len(gotIDs) != 2 || gotIDs[0] != "inc_good1" || gotIDs[1] != "inc_good2" {
		t.Errorf("ListIncidents = %v, want [inc_good1 inc_good2]", gotIDs)
	}
}

func TestListIncidentsSkipsInvalidStoredRecord(t *testing.T) {
	db := newTestStore(t)

	good := sampleIncident("inc_good")
	if err := db.SaveIncident(good); err != nil {
		t.Fatal(err)
	}

	emptyID := sampleIncident("")
	putRawIncidentRow(t, db, "inc_empty_id", mustMarshalIncident(t, emptyID))

	mismatchedID := sampleIncident("inc_value_id")
	putRawIncidentRow(t, db, "inc_key_id", mustMarshalIncident(t, mismatchedID))

	badStatus := sampleIncident("inc_bad_status")
	badStatus.Status = incident.Status("bogus")
	putRawIncidentRow(t, db, "inc_bad_status", mustMarshalIncident(t, badStatus))

	list, err := db.ListIncidents()
	if err != nil {
		t.Fatalf("ListIncidents must not fail on invalid stored rows: %v", err)
	}
	if len(list) != 1 || list[0].ID != "inc_good" {
		t.Fatalf("ListIncidents = %+v, want only inc_good", list)
	}
}

func TestCompactIncidentsSkipsCorruptRecord(t *testing.T) {
	db := newTestStore(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	stale := sampleIncident("inc_stale")
	stale.Status = incident.StatusResolved
	stale.UpdatedAt = now.Add(-31 * 24 * time.Hour)
	if err := db.SaveIncident(stale); err != nil {
		t.Fatal(err)
	}

	putRawIncidentRow(t, db, "inc_corrupt", []byte("{bad"))

	pruned, err := db.CompactIncidents(now, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("compact must not fail on corrupt row: %v", err)
	}
	if pruned != 1 {
		t.Errorf("pruned = %d, want 1 (only inc_stale)", pruned)
	}
	if _, ok, err := db.GetIncident("inc_stale"); err != nil {
		t.Fatalf("GetIncident: %v", err)
	} else if ok {
		t.Errorf("inc_stale should be gone")
	}
}
