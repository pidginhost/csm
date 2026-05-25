package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// recordingBlocker captures every block/unblock call so the undo handler's
// dispatch can be observed without a real firewall engine.
type recordingBlocker struct {
	mu       sync.Mutex
	blocked  map[string]string
	unblocks []string
}

func newRecordingBlocker() *recordingBlocker {
	return &recordingBlocker{blocked: make(map[string]string)}
}

func (b *recordingBlocker) BlockIP(ip, reason string, _ time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blocked[ip] = reason
	return nil
}

func (b *recordingBlocker) UnblockIP(ip string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.unblocks = append(b.unblocks, ip)
	delete(b.blocked, ip)
	return nil
}

func bearerRequest(method, path string, body []byte) *http.Request {
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer tok")
	return req
}

func TestUndoPendingEmptyWhenNoEntry(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	rec := httptest.NewRecorder()
	s.apiUndoPending(rec, bearerRequest("GET", "/api/v1/undo/pending", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var entry undoPendingView
	_ = json.Unmarshal(rec.Body.Bytes(), &entry)
	if entry.ID != "" {
		t.Fatalf("expected empty pending, got %+v", entry)
	}
}

func TestRecordUndoSurfacesPending(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	req := bearerRequest("POST", "/api/v1/undo/run", nil)
	id := s.recordUndoEntry(req, "threat_bulk_block", undoInverseThreatBlock,
		"Blocked 2 IPs", undoPayloadIPs{IPs: []string{"203.0.113.5", "198.51.100.7"}})
	if id == "" {
		t.Fatalf("recordUndoEntry returned empty id")
	}

	rec := httptest.NewRecorder()
	s.apiUndoPending(rec, bearerRequest("GET", "/api/v1/undo/pending", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("pending status=%d", rec.Code)
	}
	var view undoPendingView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.ID != id {
		t.Fatalf("pending id=%s want=%s", view.ID, id)
	}
	if view.Inverse != undoInverseThreatBlock {
		t.Fatalf("inverse=%s", view.Inverse)
	}
	if view.ExpiresAt.Before(view.RecordedAt) {
		t.Fatal("expires_at must be after recorded_at")
	}
}

func TestUndoRunDispatchesInverseUnblock(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	blocker := newRecordingBlocker()
	s.blocker = blocker

	id := s.recordUndoEntry(bearerRequest("POST", "/api/v1/undo/run", nil),
		"threat_bulk_block", undoInverseThreatBlock,
		"Blocked 1 IP", undoPayloadIPs{IPs: []string{"203.0.113.9"}})

	rec := httptest.NewRecorder()
	body, _ := json.Marshal(undoRunRequest{ID: id})
	s.apiUndoRun(rec, bearerRequest("POST", "/api/v1/undo/run", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("run status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp undoRunResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Count != 1 {
		t.Fatalf("count=%d want=1", resp.Count)
	}
	if resp.Inverse != undoInverseThreatBlock {
		t.Fatalf("inverse=%s", resp.Inverse)
	}

	blocker.mu.Lock()
	defer blocker.mu.Unlock()
	if len(blocker.unblocks) != 1 || blocker.unblocks[0] != "203.0.113.9" {
		t.Fatalf("expected one unblock for 203.0.113.9, got %v", blocker.unblocks)
	}
}

func TestUndoRunDispatchesInverseReblock(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	blocker := newRecordingBlocker()
	s.blocker = blocker

	id := s.recordUndoEntry(bearerRequest("POST", "/api/v1/undo/run", nil),
		"firewall_bulk_unblock", undoInverseFirewallUnblock,
		"Unblocked 2 IPs", undoPayloadIPs{
			IPs:     []string{"203.0.113.10", "203.0.113.11"},
			Reason:  "Undo: re-block via CSM Web UI",
			Timeout: "24h",
		})

	body, _ := json.Marshal(undoRunRequest{ID: id})
	rec := httptest.NewRecorder()
	s.apiUndoRun(rec, bearerRequest("POST", "/api/v1/undo/run", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("run status=%d body=%s", rec.Code, rec.Body.String())
	}

	blocker.mu.Lock()
	defer blocker.mu.Unlock()
	if len(blocker.blocked) != 2 {
		t.Fatalf("expected 2 reblocked, got %+v", blocker.blocked)
	}
	if blocker.blocked["203.0.113.10"] == "" || blocker.blocked["203.0.113.11"] == "" {
		t.Fatalf("missing IP after reblock: %+v", blocker.blocked)
	}
}

func TestUndoRunRejectsExpiredEntry(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()
	id := s.recordUndoEntry(bearerRequest("POST", "/api/v1/undo/run", nil),
		"threat_bulk_block", undoInverseThreatBlock,
		"Blocked", undoPayloadIPs{IPs: []string{"203.0.113.20"}})

	// Backdate so the entry is past TTL.
	expireUndoEntry(t, sdb, id)

	body, _ := json.Marshal(undoRunRequest{ID: id})
	rec := httptest.NewRecorder()
	s.apiUndoRun(rec, bearerRequest("POST", "/api/v1/undo/run", body))
	if rec.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestUndoRunSecondConsumptionMisses(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.blocker = newRecordingBlocker()
	id := s.recordUndoEntry(bearerRequest("POST", "/api/v1/undo/run", nil),
		"threat_bulk_block", undoInverseThreatBlock,
		"Blocked", undoPayloadIPs{IPs: []string{"203.0.113.30"}})
	body, _ := json.Marshal(undoRunRequest{ID: id})

	rec := httptest.NewRecorder()
	s.apiUndoRun(rec, bearerRequest("POST", "/api/v1/undo/run", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("first run status=%d", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.apiUndoRun(rec, bearerRequest("POST", "/api/v1/undo/run", body))
	if rec.Code != http.StatusGone {
		t.Fatalf("second run expected 410, got %d", rec.Code)
	}
}

func TestUndoRunWritesAuditEntry(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.blocker = newRecordingBlocker()
	id := s.recordUndoEntry(bearerRequest("POST", "/api/v1/undo/run", nil),
		"threat_bulk_block", undoInverseThreatBlock,
		"Blocked 1 IP", undoPayloadIPs{IPs: []string{"203.0.113.40"}})
	body, _ := json.Marshal(undoRunRequest{ID: id})

	rec := httptest.NewRecorder()
	s.apiUndoRun(rec, bearerRequest("POST", "/api/v1/undo/run", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("run status=%d", rec.Code)
	}

	entries := readUIAuditLog(s.cfg.StatePath, 20)
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Action, "undo_") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected audit entry for undo, got %+v (audit path=%s)",
			entries, filepath.Join(s.cfg.StatePath, uiAuditFile))
	}
}

// expireUndoEntry backdates the named entry's recorded_at past the TTL
// window so handlers treat it as expired, without forcing a real-time sleep.
func expireUndoEntry(t *testing.T, sdb *store.DB, id string) {
	t.Helper()
	if sdb == nil {
		t.Fatal("store unavailable")
	}
	if err := store.RewriteUndoEntryRecordedAt(sdb, id, time.Now().Add(-2*store.UndoTTL)); err != nil {
		t.Fatalf("backdate entry: %v", err)
	}
}
