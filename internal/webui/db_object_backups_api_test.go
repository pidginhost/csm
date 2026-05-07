package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// withTempStoreForWebui wires up a fresh bbolt store as the global
// for tests that need to read/write the db_object_backups bucket.
// Restores the previous global on cleanup.
func withTempStoreForWebui(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = db.Close()
	})
	return db
}

// --- listing -------------------------------------------------------------

func TestAPIDBObjectBackupsEmptyStore(t *testing.T) {
	withTempStoreForWebui(t)

	srv := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/db-object-backups", nil)
	srv.apiDBObjectBackups(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var got []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty list, got %d entries", len(got))
	}
}

func TestAPIDBObjectBackupsListsAllRecordsNewestFirst(t *testing.T) {
	db := withTempStoreForWebui(t)

	older := store.DBObjectBackup{
		Account: "alice", Schema: "alice_wp", Kind: "trigger", Name: "trg_old",
		CreateSQL: "CREATE TRIGGER trg_old ...",
		DroppedAt: time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC),
		DroppedBy: "csm-cli",
	}
	newer := store.DBObjectBackup{
		Account: "alice", Schema: "alice_wp", Kind: "event", Name: "ev_new",
		CreateSQL:  "CREATE EVENT ev_new ...",
		DroppedAt:  time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC),
		DroppedBy:  "csm-cli",
		RestoredAt: time.Date(2026, 4, 28, 11, 0, 0, 0, time.UTC),
	}
	if err := db.PutDBObjectBackup(older); err != nil {
		t.Fatalf("put older: %v", err)
	}
	if err := db.PutDBObjectBackup(newer); err != nil {
		t.Fatalf("put newer: %v", err)
	}

	srv := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/db-object-backups", nil)
	srv.apiDBObjectBackups(rr, req)

	var got []dbObjectBackupEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("entries = %d, want 2", len(got))
	}
	// Newest first: ev_new before trg_old.
	if got[0].Name != "ev_new" {
		t.Errorf("first entry = %q, want ev_new (newest)", got[0].Name)
	}
	if got[1].Name != "trg_old" {
		t.Errorf("second entry = %q, want trg_old", got[1].Name)
	}
	// Body bytes surface the CreateSQL length but not the SQL itself.
	if got[0].BodyBytes != len("CREATE EVENT ev_new ...") {
		t.Errorf("BodyBytes for ev_new = %d", got[0].BodyBytes)
	}
	if !got[0].Restored || got[0].RestoredAt == "" {
		t.Errorf("restored state missing from ev_new: %+v", got[0])
	}
	if got[1].Restored || got[1].RestoredAt != "" {
		t.Errorf("unexpected restored state on trg_old: %+v", got[1])
	}
	// Each entry must carry a key for the restore round-trip.
	for _, e := range got {
		if e.Key == "" {
			t.Errorf("entry %q missing key", e.Name)
		}
	}
}

func TestAPIDBObjectBackupPreviewReturnsBoundedCreateSQL(t *testing.T) {
	db := withTempStoreForWebui(t)
	if err := db.PutDBObjectBackup(store.DBObjectBackup{
		Account: "alice", Schema: "alice_wp", Kind: "trigger", Name: "trg_old",
		CreateSQL: strings.Repeat("A", dbObjectBackupPreviewBytes+10),
		DroppedAt: time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC),
		DroppedBy: "csm-cli",
	}); err != nil {
		t.Fatalf("put backup: %v", err)
	}
	_, keys, err := db.ListDBObjectBackupsAll()
	if err != nil {
		t.Fatalf("ListDBObjectBackupsAll: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("key count = %d, want 1", len(keys))
	}

	srv := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/db-object-backup-preview?key="+keys[0], nil)
	srv.apiDBObjectBackupPreview(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["truncated"] != true {
		t.Fatalf("truncated = %v, want true", got["truncated"])
	}
	if len(got["preview"].(string)) != dbObjectBackupPreviewBytes {
		t.Fatalf("preview length = %d", len(got["preview"].(string)))
	}
}

// --- restore -------------------------------------------------------------

func TestAPIDBObjectBackupRestoreRejectsMissingKey(t *testing.T) {
	withTempStoreForWebui(t)
	srv := &Server{}

	body := bytes.NewBufferString(`{}`)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/db-object-backup-restore", body)
	srv.apiDBObjectBackupRestore(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing key", rr.Code)
	}
}

func TestAPIDBObjectBackupRestoreRejectsGET(t *testing.T) {
	withTempStoreForWebui(t)
	srv := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/db-object-backup-restore", nil)
	srv.apiDBObjectBackupRestore(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestAPIDBObjectBackupRestoreUnknownKeyReturns400(t *testing.T) {
	withTempStoreForWebui(t)
	srv := &Server{}

	body := bytes.NewBufferString(`{"key":"alice:alice_wp:trigger:trg:0"}`)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/db-object-backup-restore", body)
	srv.apiDBObjectBackupRestore(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing key", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "not found") {
		t.Errorf("body should mention not found, got %q", rr.Body.String())
	}
}

// --- newest-first sort ---------------------------------------------------

func TestSortDBObjectBackupsNewestFirst(t *testing.T) {
	in := []dbObjectBackupEntry{
		{Name: "a", DroppedAt: "2026-04-01T10:00:00Z"},
		{Name: "c", DroppedAt: "2026-04-30T10:00:00Z"},
		{Name: "b", DroppedAt: "2026-04-15T10:00:00Z"},
	}
	sortDBObjectBackupsNewestFirst(in)
	got := []string{in[0].Name, in[1].Name, in[2].Name}
	want := []string{"c", "b", "a"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d = %q, want %q (full = %v)", i, got[i], want[i], got)
		}
	}
}
