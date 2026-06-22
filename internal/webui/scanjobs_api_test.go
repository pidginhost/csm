package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// newTestServerWithReadToken creates a Server with a read-scope Bearer token
// and a real bbolt store wired as store.Global(). The cleanup restores
// Global to nil and closes the bbolt DB.
func newTestServerWithReadToken(t *testing.T) (*Server, string) {
	t.Helper()
	const tok = "read-token"
	s := newTestServer(t, "admin-tok")
	// Add a read-scope token alongside the admin one.
	s.cfg.WebUI.Tokens = []config.WebUIToken{
		{Name: "admin", Token: "admin-tok", Scope: "admin"},
		{Name: "reader", Token: tok, Scope: "read"},
	}
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		store.SetGlobal(nil)
		_ = sdb.Close()
	})
	store.SetGlobal(sdb)
	return s, tok
}

// readGet issues a GET request with a Bearer token to the given handler and
// returns the recorder.
func readGet(s *Server, tok, path string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.requireRead(http.HandlerFunc(handler)).ServeHTTP(w, req)
	return w
}

// seedJob inserts a ScanJobRecord into the live store.Global().
func seedJob(t *testing.T, id, state string, created time.Time) store.ScanJobRecord {
	t.Helper()
	rec := store.ScanJobRecord{
		ID:      id,
		Scope:   "account",
		Target:  "198.51.100.1", // RFC 5737
		State:   state,
		Created: created,
	}
	if err := store.Global().PutScanJob(rec); err != nil {
		t.Fatalf("PutScanJob: %v", err)
	}
	return rec
}

// seedFinding appends one finding to the job's findings bucket.
func seedFinding(t *testing.T, jobID string, seq int, check string) {
	t.Helper()
	f := alert.Finding{
		Check:    check,
		Severity: alert.Warning,
		Message:  "test finding for 198.51.100.1",
	}
	if err := store.Global().AppendScanJobFinding(jobID, seq, f); err != nil {
		t.Fatalf("AppendScanJobFinding: %v", err)
	}
}

// --- Test 1: List returns seeded jobs newest-first, read-scope allowed ---

func TestScanJobsList_ReadScopeAllowed(t *testing.T) {
	s, tok := newTestServerWithReadToken(t)

	now := time.Now()
	seedJob(t, "job-older", "done", now.Add(-time.Hour))
	seedJob(t, "job-newer", "done", now)

	w := readGet(s, tok, "/api/v1/scan-jobs", s.apiScanJobsList)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Jobs []store.ScanJobRecord `json:"jobs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Jobs) != 2 {
		t.Fatalf("job count = %d, want 2", len(resp.Jobs))
	}
	// Newest first
	if resp.Jobs[0].ID != "job-newer" {
		t.Errorf("first job = %q, want job-newer (newest first)", resp.Jobs[0].ID)
	}
	if resp.Jobs[1].ID != "job-older" {
		t.Errorf("second job = %q, want job-older", resp.Jobs[1].ID)
	}
}

func TestScanJobsList_EmptyWhenNoJobs(t *testing.T) {
	s, tok := newTestServerWithReadToken(t)

	w := readGet(s, tok, "/api/v1/scan-jobs", s.apiScanJobsList)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp struct {
		Jobs []store.ScanJobRecord `json:"jobs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Jobs == nil {
		t.Error("jobs field must be [] not null")
	}
}

// --- Test 2: Detail returns job; unknown ID → 404 ---

func TestScanJobsRouter_Detail_Found(t *testing.T) {
	s, tok := newTestServerWithReadToken(t)
	seedJob(t, "job-abc", "running", time.Now())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs/job-abc", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.requireRead(http.HandlerFunc(s.apiScanJobsRouter)).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Job store.ScanJobRecord `json:"job"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Job.ID != "job-abc" {
		t.Errorf("job.id = %q, want job-abc", resp.Job.ID)
	}
}

func TestScanJobsRouter_Detail_NotFound(t *testing.T) {
	s, tok := newTestServerWithReadToken(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs/nonexistent-id", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.requireRead(http.HandlerFunc(s.apiScanJobsRouter)).ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// --- Test 3: Findings pagination ---

func TestScanJobsRouter_Findings_Pagination(t *testing.T) {
	s, tok := newTestServerWithReadToken(t)
	const jobID = "job-paginate"
	seedJob(t, jobID, "done", time.Now())
	for i := 0; i < 5; i++ {
		seedFinding(t, jobID, i, "webshell")
	}

	// Request page 2: offset=2, limit=2 → findings[2] and findings[3], total=5
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs/"+jobID+"/findings?offset=2&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.requireRead(http.HandlerFunc(s.apiScanJobsRouter)).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		JobID    string          `json:"job_id"`
		Findings []alert.Finding `json:"findings"`
		Total    int             `json:"total"`
		Offset   int             `json:"offset"`
		Limit    int             `json:"limit"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Total != 5 {
		t.Errorf("total = %d, want 5", resp.Total)
	}
	if len(resp.Findings) != 2 {
		t.Errorf("page len = %d, want 2", len(resp.Findings))
	}
	if resp.Offset != 2 {
		t.Errorf("offset = %d, want 2", resp.Offset)
	}
	if resp.Limit != 2 {
		t.Errorf("limit = %d, want 2", resp.Limit)
	}
	if resp.JobID != jobID {
		t.Errorf("job_id = %q, want %q", resp.JobID, jobID)
	}
}

func TestScanJobsRouter_Findings_NilBecomesEmpty(t *testing.T) {
	s, tok := newTestServerWithReadToken(t)
	const jobID = "job-empty-findings"
	seedJob(t, jobID, "done", time.Now())
	// No findings seeded.

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs/"+jobID+"/findings", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.requireRead(http.HandlerFunc(s.apiScanJobsRouter)).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp struct {
		Findings []alert.Finding `json:"findings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Findings == nil {
		t.Error("findings must be [] not null")
	}
}

// --- Test 4: store.Global()==nil → 503 ---

func TestScanJobsList_StoreNil_503(t *testing.T) {
	s := newTestServer(t, "admin-tok")
	// Deliberately do NOT set store.Global().
	store.SetGlobal(nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	s.apiScanJobsList(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestScanJobsRouter_StoreNil_503(t *testing.T) {
	s := newTestServer(t, "admin-tok")
	store.SetGlobal(nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs/any-id", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	s.apiScanJobsRouter(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

// --- Test 5: non-GET method on the routes → 405 ---

func TestScanJobsList_PostRejected(t *testing.T) {
	s, tok := newTestServerWithReadToken(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.requireRead(http.HandlerFunc(s.apiScanJobsList)).ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestScanJobsRouter_PostRejected(t *testing.T) {
	s, tok := newTestServerWithReadToken(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/job-abc", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.requireRead(http.HandlerFunc(s.apiScanJobsRouter)).ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

// --- Extra: empty-id and unknown tail → 404 / 400 ---

func TestScanJobsRouter_EmptyID_400(t *testing.T) {
	s, tok := newTestServerWithReadToken(t)

	w := httptest.NewRecorder()
	// Path that results in empty tail after prefix strip
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.apiScanJobsRouter(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestScanJobsRouter_UnknownTail_404(t *testing.T) {
	s, tok := newTestServerWithReadToken(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs/job-x/unknown-action", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.apiScanJobsRouter(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}
