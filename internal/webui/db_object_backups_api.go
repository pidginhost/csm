package webui

import (
	"net/http"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

// Cleanup-history handlers for the db_object_backups bbolt bucket.
// htaccess pre_clean backups already surface through the existing
// /api/v1/quarantine listing (their .meta sidecars now match the
// JSON QuarantineMeta shape). The bbolt-backed db_object_backups
// bucket needs its own list + restore endpoints because the data
// lives outside the filesystem-quarantine flow.
//
// All handlers are registered behind requireAuth in server.go;
// the restore handler additionally requires CSRF.

// dbObjectBackupEntry is the JSON shape returned to the cleanup-
// history UI. The Key field is opaque to the UI -- it round-trips
// to the restore endpoint as-is so the lookup is a single bbolt
// Get, not a multi-field reconstruction.
type dbObjectBackupEntry struct {
	Key        string `json:"key"`
	Account    string `json:"account"`
	Schema     string `json:"schema"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	DroppedAt  string `json:"dropped_at"` // RFC 3339
	DroppedBy  string `json:"dropped_by"`
	FindingID  string `json:"finding_id,omitempty"`
	BodyBytes  int    `json:"body_bytes"` // length of CreateSQL; surfaced for size hint
	RestoredAt string `json:"restored_at,omitempty"`
	Restored   bool   `json:"restored"`
}

const dbObjectBackupPreviewBytes = 8 * 1024

// apiDBObjectBackups returns every record in the bucket, newest
// first by DroppedAt. The full CreateSQL is intentionally NOT
// returned in the listing -- those payloads can be large and the
// listing is meant for browse-and-pick. The preview endpoint returns
// one bounded CREATE SQL payload on demand.
func (s *Server) apiDBObjectBackups(w http.ResponseWriter, _ *http.Request) {
	sdb := store.Global()
	if sdb == nil {
		writeJSON(w, []dbObjectBackupEntry{})
		return
	}
	records, keys, err := sdb.ListDBObjectBackupsAll()
	if err != nil {
		writeJSONError(w, "failed to list backups: "+err.Error(), http.StatusInternalServerError)
		return
	}

	out := make([]dbObjectBackupEntry, 0, len(records))
	for i, r := range records {
		entry := dbObjectBackupEntry{
			Key:       keys[i],
			Account:   r.Account,
			Schema:    r.Schema,
			Kind:      r.Kind,
			Name:      r.Name,
			DroppedAt: r.DroppedAt.UTC().Format("2006-01-02T15:04:05Z"),
			DroppedBy: r.DroppedBy,
			FindingID: r.FindingID,
			BodyBytes: len(r.CreateSQL),
		}
		if !r.RestoredAt.IsZero() {
			entry.Restored = true
			entry.RestoredAt = r.RestoredAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		out = append(out, entry)
	}
	// Newest first -- the bbolt key embeds unix-nanos so a string
	// sort already produces chronological-by-drop-time when
	// reversed. Doing it in Go keeps the contract explicit.
	sortDBObjectBackupsNewestFirst(out)

	writeJSON(w, out)
}

// apiDBObjectBackupPreview returns a bounded CREATE SQL preview for one
// backup. Full restore still round-trips only the opaque key.
func (s *Server) apiDBObjectBackupPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		writeJSONError(w, "key is required", http.StatusBadRequest)
		return
	}
	sdb := store.Global()
	if sdb == nil {
		writeJSONError(w, "bbolt store not available", http.StatusServiceUnavailable)
		return
	}
	rec, ok, err := sdb.GetDBObjectBackupByKey(key)
	if err != nil {
		writeJSONError(w, "failed to read backup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		writeJSONError(w, "backup not found", http.StatusNotFound)
		return
	}
	preview := rec.CreateSQL
	truncated := false
	if len(preview) > dbObjectBackupPreviewBytes {
		preview = preview[:dbObjectBackupPreviewBytes]
		truncated = true
	}
	writeJSON(w, map[string]any{
		"key":        key,
		"account":    rec.Account,
		"schema":     rec.Schema,
		"kind":       rec.Kind,
		"name":       rec.Name,
		"preview":    preview,
		"truncated":  truncated,
		"total_size": len(rec.CreateSQL),
	})
}

// apiDBObjectBackupRestore re-executes the captured CREATE SQL.
// POST body: {"key": "<bbolt key>"}. The handler delegates to
// checks.RestoreDBObjectBackup; CSRF is enforced upstream in
// server.go's requireCSRF wrapper.
func (s *Server) apiDBObjectBackupRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if err := decodeJSONBodyLimited(w, r, 16*1024, &req); err != nil || req.Key == "" {
		writeJSONError(w, "key is required", http.StatusBadRequest)
		return
	}

	result := checks.RestoreDBObjectBackup(req.Key)
	if !result.Success {
		writeJSONError(w, result.Message, http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{
		"success": true,
		"message": result.Message,
		"details": result.Details,
	})
}

// sortDBObjectBackupsNewestFirst sorts in place by DroppedAt
// descending. Local helper rather than relying on sort.Slice so
// the comparator is unambiguous in code review.
func sortDBObjectBackupsNewestFirst(entries []dbObjectBackupEntry) {
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j].DroppedAt > entries[j-1].DroppedAt; j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
}
