package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// fakeScanJobController is an injectable ScanJobController for tests.
// It records Enqueue/Cancel calls and returns configured responses.
type fakeScanJobController struct {
	enqueueID  string
	enqueueErr error
	cancelErr  error

	// recorded call params
	lastScope      string
	lastTarget     string
	lastOpts       checks.AccountScanOptions
	lastQuarantine bool
	lastCancelID   string
}

func (f *fakeScanJobController) Enqueue(scope, target string, opts checks.AccountScanOptions, quarantine bool) (string, error) {
	f.lastScope = scope
	f.lastTarget = target
	f.lastOpts = opts
	f.lastQuarantine = quarantine
	return f.enqueueID, f.enqueueErr
}

func (f *fakeScanJobController) Cancel(id string) error {
	f.lastCancelID = id
	return f.cancelErr
}

// newTestServerWithFakeScanJobs creates a Server with both an admin and a
// read-scope token, a live bbolt store, and a fakeScanJobController wired in.
func newTestServerWithFakeScanJobs(t *testing.T) (*Server, string, string, *fakeScanJobController) {
	t.Helper()
	const adminTok = "admin-tok"
	const readTok = "read-tok"
	s := newTestServer(t, adminTok)
	s.cfg.WebUI.Tokens = []config.WebUIToken{
		{Name: "admin", Token: adminTok, Scope: "admin"},
		{Name: "reader", Token: readTok, Scope: "read"},
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
	fc := &fakeScanJobController{enqueueID: "sj-test-001"}
	s.SetScanJobs(fc)
	return s, adminTok, readTok, fc
}

// adminPost issues a POST request with an admin Bearer token directly to the
// server mux (full dispatch, including middleware). Optionally adds CSRF header
// if withCSRF is true (admin bearer already bypasses CSRF, but included for
// completeness). The body is JSON-marshaled from bodyVal.
func adminPost(s *Server, path string, bodyVal any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(bodyVal)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer admin-tok")
	s.httpSrv.Handler.ServeHTTP(w, req)
	return w
}

// readPost issues a POST request with a read-scope Bearer token to the server
// mux and returns the recorder.
func readPost(s *Server, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Authorization", "Bearer read-tok")
	s.httpSrv.Handler.ServeHTTP(w, req)
	return w
}

// cookiePost issues a POST request authenticated via csm_auth cookie (not
// bearer). The caller controls whether a CSRF header is set.
func cookiePost(s *Server, adminTok, path string, withCSRF bool, bodyVal any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(bodyVal)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "csm_auth", Value: adminTok})
	if withCSRF {
		req.Header.Set("X-CSRF-Token", s.csrfToken())
	}
	s.httpSrv.Handler.ServeHTTP(w, req)
	return w
}

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

// --- C3 POST endpoint tests ---

// Test 1: POST enqueue with a read-scope token → 401/403.
func TestScanJobsEnqueue_ReadTokenRejected(t *testing.T) {
	s, _, _, _ := newTestServerWithFakeScanJobs(t)

	w := readPost(s, "/api/v1/scan-jobs")
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 401 or 403 (read token must not enqueue)", w.Code)
	}
}

// Test 2: POST enqueue with admin cookie but missing CSRF → 403.
func TestScanJobsEnqueue_AdminCookieMissingCSRF_403(t *testing.T) {
	s, adminTok, _, _ := newTestServerWithFakeScanJobs(t)

	w := cookiePost(s, adminTok, "/api/v1/scan-jobs", false, map[string]any{
		"scope":  "account",
		"target": "203.0.113.example",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (CSRF required for cookie sessions)", w.Code)
	}
}

// Test 3: POST enqueue with admin bearer + valid body → 200, job_id returned,
// fake controller receives correct scope/target/opts/quarantine.
func TestScanJobsEnqueue_AdminBearer_Success(t *testing.T) {
	s, _, _, fc := newTestServerWithFakeScanJobs(t)

	w := adminPost(s, "/api/v1/scan-jobs", map[string]any{
		"scope":           "account",
		"target":          "testuser",
		"respect_ignores": true,
		"quarantine":      false,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		JobID string `json:"job_id"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.JobID == "" {
		t.Error("job_id must not be empty")
	}
	if resp.State != "queued" {
		t.Errorf("state = %q, want queued", resp.State)
	}
	if fc.lastScope != "account" {
		t.Errorf("scope = %q, want account", fc.lastScope)
	}
	if fc.lastTarget != "testuser" {
		t.Errorf("target = %q, want testuser", fc.lastTarget)
	}
	if !fc.lastOpts.RespectIgnores {
		t.Error("RespectIgnores must be true")
	}
	if fc.lastOpts.MaxFiles != 0 {
		t.Errorf("MaxFiles = %d, want 0 (full scan)", fc.lastOpts.MaxFiles)
	}
	if !fc.lastOpts.ForceContent {
		t.Error("ForceContent must be true")
	}
	if !fc.lastOpts.ForceFileIndex {
		t.Error("ForceFileIndex must be true")
	}
}

// Test 4: POST enqueue scope="all" with quarantine=true → 400.
func TestScanJobsEnqueue_AllScopeWithQuarantine_400(t *testing.T) {
	s, _, _, _ := newTestServerWithFakeScanJobs(t)

	w := adminPost(s, "/api/v1/scan-jobs", map[string]any{
		"scope":      "all",
		"quarantine": true,
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (quarantine rejected for scope=all)", w.Code)
	}
}

// Test 5: POST enqueue scope="account" with invalid target → 400.
func TestScanJobsEnqueue_AccountScopeInvalidTarget_400(t *testing.T) {
	s, _, _, _ := newTestServerWithFakeScanJobs(t)

	w := adminPost(s, "/api/v1/scan-jobs", map[string]any{
		"scope":  "account",
		"target": "../etc",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (path-like target rejected)", w.Code)
	}
}

// Test 6a: POST cancel with read token → 401/403.
func TestScanJobsCancel_ReadTokenRejected(t *testing.T) {
	s, _, _, _ := newTestServerWithFakeScanJobs(t)

	w := readPost(s, "/api/v1/scan-jobs/sj-test-001/cancel")
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 401 or 403 (read token must not cancel)", w.Code)
	}
}

// Test 6b: POST cancel with admin bearer → calls controller.Cancel with parsed id.
func TestScanJobsCancel_AdminBearer_Success(t *testing.T) {
	s, _, _, fc := newTestServerWithFakeScanJobs(t)

	w := adminPost(s, "/api/v1/scan-jobs/sj-test-001/cancel", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		JobID string `json:"job_id"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.JobID != "sj-test-001" {
		t.Errorf("job_id = %q, want sj-test-001", resp.JobID)
	}
	if resp.State != "canceling" {
		t.Errorf("state = %q, want canceling", resp.State)
	}
	if fc.lastCancelID != "sj-test-001" {
		t.Errorf("Cancel called with id %q, want sj-test-001", fc.lastCancelID)
	}
}

// Test 7: GET endpoints still work with a read token (C2 regression guard).
func TestScanJobsGET_ReadTokenStillAllowed(t *testing.T) {
	s, readTok := newTestServerWithReadToken(t)
	seedJob(t, "job-rg", "done", time.Now())

	// GET /api/v1/scan-jobs (list)
	wList := httptest.NewRecorder()
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs", nil)
	reqList.Header.Set("Authorization", "Bearer "+readTok)
	s.httpSrv.Handler.ServeHTTP(wList, reqList)
	if wList.Code != http.StatusOK {
		t.Errorf("GET /api/v1/scan-jobs status = %d, want 200 (read token must still work)", wList.Code)
	}

	// GET /api/v1/scan-jobs/{id} (detail)
	wDetail := httptest.NewRecorder()
	reqDetail := httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs/job-rg", nil)
	reqDetail.Header.Set("Authorization", "Bearer "+readTok)
	s.httpSrv.Handler.ServeHTTP(wDetail, reqDetail)
	if wDetail.Code != http.StatusOK {
		t.Errorf("GET /api/v1/scan-jobs/{id} status = %d, want 200 (read token must still work)", wDetail.Code)
	}
}

// Test 8: nil controller → POST enqueue returns 503.
func TestScanJobsEnqueue_NilController_503(t *testing.T) {
	s, _, _, _ := newTestServerWithFakeScanJobs(t)
	s.scanJobs = nil // deliberately unset

	w := adminPost(s, "/api/v1/scan-jobs", map[string]any{
		"scope":  "account",
		"target": "testuser",
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (nil controller)", w.Code)
	}
}
