package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/systemdrun"
)

// withHardeningUndoNames stands in for the root worker's record directory.
func withHardeningUndoNames(t *testing.T, list func() ([]string, error)) {
	t.Helper()
	prev := hardeningUndoNames
	hardeningUndoNames = list
	t.Cleanup(func() { hardeningUndoNames = prev })
}

type undoActionSink struct {
	mu      sync.Mutex
	records []actionlog.Record
}

func (s *undoActionSink) Write(r actionlog.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, r)
	return nil
}

func (s *undoActionSink) all() []actionlog.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.records)
}

func withUndoActionSink(t *testing.T) *undoActionSink {
	t.Helper()
	sink := &undoActionSink{}
	actionlog.SetSink(sink, "")
	t.Cleanup(func() { actionlog.SetSink(nil, "") })
	return sink
}

// undoTestReport is a saved audit: two fixes CSM applied and one it did not.
func undoTestReport() *store.AuditReport {
	return &store.AuditReport{Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), ServerType: "cpanel", Score: 2, Total: 3,
		Results: []store.AuditResult{
			{Category: "ssh", Name: "ssh_use_dns", Title: "UseDNS", Status: "pass", Message: "UseDNS no"},
			{Category: "ssh", Name: "ssh_x11_forwarding", Title: "X11Forwarding", Status: "warn", Message: "X11Forwarding yes", AutoFix: "Sets X11Forwarding no."},
			{Category: "cpanel", Name: "cp_max_emails_hour", Title: "Max emails per hour", Status: "pass", Message: "200"},
		},
	}
}

func saveUndoTestReport(t *testing.T) (*store.DB, *store.AuditReport) {
	t.Helper()
	db := withTempStoreForWebui(t)
	saved := undoTestReport()
	if err := db.SaveHardeningReport(saved); err != nil {
		t.Fatal(err)
	}
	return db, saved
}

func postHardeningUndo(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hardening/undo", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer tok")
	s.apiHardeningUndo(rec, req)
	return rec
}

type hardeningUndoReply struct {
	OK     bool                      `json:"ok"`
	Result checks.HardeningFixResult `json:"result"`
	store.AuditReport
}

func undoMarked(results []store.AuditResult) []string {
	var names []string
	for _, r := range results {
		if r.UndoAvailable {
			names = append(names, r.Name)
		}
	}
	return names
}

// checkUndoMarks fails unless exactly the results named in records offer
// Undo. os_tmp_permissions is in every fresh audit, so a recheck always has
// one result to mark.
func checkUndoMarks(t *testing.T, results []store.AuditResult, records []string) {
	t.Helper()
	seen := false
	for _, r := range results {
		if r.UndoAvailable != slices.Contains(records, r.Name) {
			t.Errorf("%s: undo_available = %v with records %v", r.Name, r.UndoAvailable, records)
		}
		seen = seen || (r.Name == "os_tmp_permissions" && r.UndoAvailable)
	}
	if slices.Contains(records, "os_tmp_permissions") && !seen {
		t.Errorf("os_tmp_permissions not offered for undo in %d results", len(results))
	}
}

// The hardening page offers Undo on each check whose fix has a record in the
// root worker's directory, after every reply that re-renders the page. The
// flag is worked out when a report is served and is never saved.
func TestHardeningReportMarksUndoAvailable(t *testing.T) {
	records := []string{"os_tmp_permissions", "ssh_use_dns"}
	withHardeningUndoNames(t, func() ([]string, error) { return slices.Clone(records), nil })

	t.Run("saved report", func(t *testing.T) {
		s := newTestServer(t, "tok")
		db, saved := saveUndoTestReport(t)
		rec := httptest.NewRecorder()
		s.apiHardening(rec, httptest.NewRequest(http.MethodGet, "/api/v1/hardening", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var got store.AuditReport
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if marked := undoMarked(got.Results); !slices.Equal(marked, []string{"ssh_use_dns"}) {
			t.Fatalf("undo offered for %v", marked)
		}
		for i := range got.Results {
			got.Results[i].UndoAvailable = false
		}
		if !reflect.DeepEqual(got, *saved) {
			t.Errorf("saved audit fields changed: %+v", got)
		}
		if stored, err := db.LoadHardeningReport(); err != nil || !reflect.DeepEqual(stored, saved) {
			t.Errorf("GET rewrote the saved report: %+v, %v", stored, err)
		}
	})

	for name, call := range map[string]func(*testing.T, *Server) *httptest.ResponseRecorder{
		"audit run": func(_ *testing.T, s *Server) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			s.apiHardeningRun(rec, httptest.NewRequest(http.MethodPost, "/api/v1/hardening/run", nil))
			return rec
		},
		"apply recheck": func(t *testing.T, s *Server) *httptest.ResponseRecorder {
			s.hardeningApply = func(context.Context, *config.Config, checks.HardeningApplyRequest) ([]checks.HardeningFixResult, error) {
				return []checks.HardeningFixResult{{Name: "os_tmp_permissions", Title: "/tmp Permissions", Status: "applied", Message: "ok"}}, nil
			}
			return postHardeningApply(t, s, `{"category":"os","names":["os_tmp_permissions"]}`)
		},
		"apply failure recheck": func(t *testing.T, s *Server) *httptest.ResponseRecorder {
			s.hardeningApply = func(context.Context, *config.Config, checks.HardeningApplyRequest) ([]checks.HardeningFixResult, error) {
				return nil, errors.New("hardening worker: signal: killed")
			}
			return postHardeningApply(t, s, `{"category":"os"}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestServer(t, "tok")
			db, _ := saveUndoTestReport(t)
			rec := call(t, s)
			var got struct {
				store.AuditReport
				Report *store.AuditReport `json:"report"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			report := &got.AuditReport
			if rec.Code != http.StatusOK {
				report = got.Report
			}
			if report == nil || len(report.Results) == 0 {
				t.Fatalf("status %d, no report: %s", rec.Code, rec.Body.String())
			}
			checkUndoMarks(t, report.Results, records)
			stored, err := db.LoadHardeningReport()
			if err != nil || !stored.Timestamp.Equal(report.Timestamp) {
				t.Fatalf("recheck not saved: %v", err)
			}
			if marked := undoMarked(stored.Results); len(marked) != 0 {
				t.Errorf("undo flags saved for %v", marked)
			}
		})
	}

	t.Run("records unreadable", func(t *testing.T) {
		withHardeningUndoNames(t, func() ([]string, error) { return nil, errors.New("not a root-owned 0700 directory") })
		s := newTestServer(t, "tok")
		db, saved := saveUndoTestReport(t)
		// Only the record directory says what can be undone, never a saved report.
		saved.Results[0].UndoAvailable = true
		if err := db.SaveHardeningReport(saved); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		s.apiHardening(rec, httptest.NewRequest(http.MethodGet, "/api/v1/hardening", nil))
		var got store.AuditReport
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK || len(got.Results) != 3 {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		if marked := undoMarked(got.Results); len(marked) != 0 {
			t.Errorf("undo offered for %v without readable records", marked)
		}
	})
}

// The handler hands only the fix name to the root worker, logs the outcome
// to the action log and the UI audit log, and re-runs and saves the audit:
// an undone or failed undo may have changed the host.
func TestHardeningUndoAPIRunsWorkerAndReaudits(t *testing.T) {
	for _, tc := range []struct {
		status    string
		result    actionlog.Result
		errorText string
	}{
		{"undone", actionlog.Applied, ""},
		{"failed", actionlog.Failed, "/tmp failed."},
	} {
		t.Run(tc.status, func(t *testing.T) {
			s := newTestServer(t, "tok")
			db, saved := saveUndoTestReport(t)
			sink := withUndoActionSink(t)
			records := []string{"os_tmp_permissions", "ssh_use_dns"}
			withHardeningUndoNames(t, func() ([]string, error) { return slices.Clone(records), nil })
			var asked []string
			s.hardeningUndo = func(_ context.Context, _ *config.Config, name string) (checks.HardeningFixResult, error) {
				asked = append(asked, name)
				if tc.status == "undone" {
					records = slices.DeleteFunc(records, func(n string) bool { return n == name })
				}
				return checks.HardeningFixResult{Name: name, Title: name, Status: tc.status, Message: "/tmp " + tc.status + "."}, nil
			}

			// os_tmp_permissions is in every fresh audit, so its Undo must go.
			rec := postHardeningUndo(t, s, `{"name":"os_tmp_permissions"}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			if !slices.Equal(asked, []string{"os_tmp_permissions"}) {
				t.Fatalf("worker asked for %v", asked)
			}
			var got hardeningUndoReply
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			want := checks.HardeningFixResult{Name: "os_tmp_permissions", Title: "os_tmp_permissions", Status: tc.status, Message: "/tmp " + tc.status + "."}
			if !got.OK || got.Result != want {
				t.Fatalf("reply = %s", rec.Body.String())
			}
			if got.Timestamp.Equal(saved.Timestamp) || len(got.Results) == 0 {
				t.Fatalf("audit not re-run: %s", rec.Body.String())
			}
			checkUndoMarks(t, got.Results, records)
			if stored, err := db.LoadHardeningReport(); err != nil || !stored.Timestamp.Equal(got.Timestamp) {
				t.Fatalf("recheck not saved: %v", err)
			}

			acts := sink.all()
			if len(acts) != 1 {
				t.Fatalf("action records = %+v", acts)
			}
			a := acts[0]
			if a.Op != "operate.undo_hardening" || a.Target != "os_tmp_permissions" || a.Result != tc.result || a.Error != tc.errorText ||
				a.Actor != actionlog.WebUI || a.ActorDetail != "legacy-auth-token" {
				t.Errorf("action record = %+v", a)
			}
			entries := readUIAuditLog(s.cfg.StatePath, 0)
			if len(entries) != 1 || entries[0].Action != "hardening_undo" || entries[0].Target != "os_tmp_permissions" ||
				entries[0].Details != tc.status+": /tmp "+tc.status+"." {
				t.Errorf("audit log = %+v", entries)
			}
		})
	}

	t.Run("worker error", func(t *testing.T) {
		s := newTestServer(t, "tok")
		db, saved := saveUndoTestReport(t)
		sink := withUndoActionSink(t)
		withHardeningUndoNames(t, func() ([]string, error) { return []string{"os_tmp_permissions"}, nil })
		s.hardeningUndo = func(context.Context, *config.Config, string) (checks.HardeningFixResult, error) {
			return checks.HardeningFixResult{}, errors.New("hardening worker: signal: killed")
		}
		rec := postHardeningUndo(t, s, `{"name":"ssh_use_dns"}`)
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "signal: killed") ||
			!strings.Contains(rec.Body.String(), "audit was re-run") {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var body struct {
			Report *store.AuditReport `json:"report"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Report == nil || body.Report.Timestamp.Equal(saved.Timestamp) {
			t.Fatalf("no fresh report: %s", rec.Body.String())
		}
		checkUndoMarks(t, body.Report.Results, []string{"os_tmp_permissions"})
		if stored, err := db.LoadHardeningReport(); err != nil || !stored.Timestamp.Equal(body.Report.Timestamp) {
			t.Fatalf("recheck not saved: %v", err)
		}
		acts := sink.all()
		if len(acts) != 1 || acts[0].Result != actionlog.Failed || acts[0].Error != "hardening worker: signal: killed" {
			t.Errorf("action records = %+v", acts)
		}
		if entries := readUIAuditLog(s.cfg.StatePath, 0); len(entries) != 1 || entries[0].Details != "error: hardening worker: signal: killed" {
			t.Errorf("audit log = %+v", entries)
		}
	})
}

// A request the worker would not run is refused before the worker starts.
func TestHardeningUndoAPIRejects(t *testing.T) {
	s := newTestServer(t, "tok")
	s.hardeningUndo = func(context.Context, *config.Config, string) (checks.HardeningFixResult, error) {
		t.Error("worker started for a rejected request")
		return checks.HardeningFixResult{}, nil
	}
	for _, tc := range []struct {
		method, body string
		want         int
	}{
		{http.MethodGet, "", http.StatusMethodNotAllowed},
		{http.MethodPost, `{"name":"nope"}`, http.StatusBadRequest},
		{http.MethodPost, `{"name":"../shadow"}`, http.StatusBadRequest},
		{http.MethodPost, `{}`, http.StatusBadRequest},
		{http.MethodPost, `{"name":"ssh_use_dns","extra":1}`, http.StatusBadRequest},
		{http.MethodPost, `{"name":"ssh_use_dns","name":"cp_updates"}`, http.StatusBadRequest},
		{http.MethodPost, `{"name":["ssh_use_dns"]}`, http.StatusBadRequest},
		{http.MethodPost, `{"name":`, http.StatusBadRequest},
		{http.MethodPost, `{"name":"ssh_use_dns"}` + strings.Repeat(" ", 1<<14), http.StatusBadRequest},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, "/api/v1/hardening/undo", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		s.apiHardeningUndo(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s %.60q: status %d, want %d", tc.method, tc.body, rec.Code, tc.want)
		}
	}

	// A browser session without the CSRF token stops at the middleware.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hardening/undo", strings.NewReader(`{"name":"ssh_use_dns"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(testBrowserCookie(t, s, "tok"))
	rec := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "Invalid CSRF token") {
		t.Errorf("without CSRF: status %d: %s", rec.Code, rec.Body.String())
	}

	// An audit, apply or other undo holds the scan lock.
	if !s.acquireScan() {
		t.Fatal("could not take the scan lock")
	}
	defer s.releaseScan()
	if rec := postHardeningUndo(t, s, `{"name":"ssh_use_dns"}`); rec.Code != http.StatusConflict {
		t.Errorf("during a scan: status %d", rec.Code)
	}
}

// A refused undo changed nothing, so the saved audit still describes the
// host: it is not re-run, and the reply carries the refusal with that report.
func TestHardeningUndoAPIRefusedKeepsReport(t *testing.T) {
	s := newTestServer(t, "tok")
	db, saved := saveUndoTestReport(t)
	sink := withUndoActionSink(t)
	withHardeningUndoNames(t, func() ([]string, error) { return []string{"cp_max_emails_hour"}, nil })
	const why = "maxemailsperhour had no value before the apply, and whmapi1 cannot remove one. Set it back to its default in WHM Tweak Settings."
	s.hardeningUndo = func(_ context.Context, _ *config.Config, name string) (checks.HardeningFixResult, error) {
		return checks.HardeningFixResult{Name: name, Title: name, Status: "refused", Message: why}, nil
	}

	rec := postHardeningUndo(t, s, `{"name":"cp_max_emails_hour"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got hardeningUndoReply
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.OK || got.Result != (checks.HardeningFixResult{Name: "cp_max_emails_hour", Title: "cp_max_emails_hour", Status: "refused", Message: why}) {
		t.Fatalf("reply = %s", rec.Body.String())
	}
	if marked := undoMarked(got.Results); !slices.Equal(marked, []string{"cp_max_emails_hour"}) {
		t.Errorf("undo offered for %v", marked)
	}
	for i := range got.Results {
		got.Results[i].UndoAvailable = false
	}
	if !reflect.DeepEqual(got.AuditReport, *saved) {
		t.Errorf("reply report = %+v, want the saved one", got.AuditReport)
	}
	if stored, err := db.LoadHardeningReport(); err != nil || !reflect.DeepEqual(stored, saved) {
		t.Errorf("saved report changed: %+v, %v", stored, err)
	}
	acts := sink.all()
	if len(acts) != 1 || acts[0].Op != "operate.undo_hardening" || acts[0].Target != "cp_max_emails_hour" ||
		acts[0].Result != actionlog.Refused || acts[0].Error != why {
		t.Errorf("action records = %+v", acts)
	}
	if entries := readUIAuditLog(s.cfg.StatePath, 0); len(entries) != 1 || entries[0].Details != "refused: "+why {
		t.Errorf("audit log = %+v", entries)
	}
}

// When the saved report cannot be read, a refused undo still says why.
func TestHardeningUndoAPIRefusedWithoutSavedReport(t *testing.T) {
	s := newTestServer(t, "tok")
	db, _ := saveUndoTestReport(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	const why = "The WHM tweak setting maxemailsperhour changed since the apply."
	s.hardeningUndo = func(_ context.Context, _ *config.Config, name string) (checks.HardeningFixResult, error) {
		return checks.HardeningFixResult{Name: name, Title: name, Status: "refused", Message: why}, nil
	}
	rec := postHardeningUndo(t, s, `{"name":"cp_max_emails_hour"}`)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), why) || !strings.Contains(rec.Body.String(), "failed to load") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

// Without systemd-run the worker never starts, so nothing was undone: the
// saved audit stays and no action is recorded.
func TestHardeningUndoAPIWithoutSystemdRunChangesNothing(t *testing.T) {
	s := newTestServer(t, "tok")
	db, saved := saveUndoTestReport(t)
	sink := withUndoActionSink(t)
	s.hardeningUndo = func(context.Context, *config.Config, string) (checks.HardeningFixResult, error) {
		return checks.HardeningFixResult{}, fmt.Errorf("%w: systemd-run not found", systemdrun.ErrUnavailable)
	}
	rec := postHardeningUndo(t, s, `{"name":"ssh_use_dns"}`)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "nothing was changed") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if stored, err := db.LoadHardeningReport(); err != nil || !reflect.DeepEqual(stored, saved) {
		t.Errorf("saved report changed: %+v, %v", stored, err)
	}
	if acts := sink.all(); len(acts) != 0 {
		t.Errorf("action records = %+v", acts)
	}
	if entries := readUIAuditLog(s.cfg.StatePath, 0); len(entries) != 1 || !strings.HasPrefix(entries[0].Details, "not started: ") {
		t.Errorf("audit log = %+v", entries)
	}
}

// The worker keeps running when the browser goes away, and the reply waits
// for the worker and the recheck after it.
func TestHardeningUndoAPIAllowsTimeForWorkerAndRecheck(t *testing.T) {
	s := newTestServer(t, "tok")
	w := newDeadlineRecorder()
	var workerDeadline time.Time
	var workerErr error
	s.hardeningUndo = func(ctx context.Context, _ *config.Config, name string) (checks.HardeningFixResult, error) {
		workerDeadline, _ = ctx.Deadline()
		workerErr = ctx.Err()
		return checks.HardeningFixResult{Name: name, Title: name, Status: "undone"}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hardening/undo", strings.NewReader(`{"name":"ssh_use_dns"}`)).WithContext(ctx)
	s.apiHardeningUndo(w, req)
	_, deadlines, _ := w.snapshot()
	if w.status != http.StatusOK || workerErr != nil || workerDeadline.Before(start.Add(checks.HardeningApplyWorkerTimeout)) ||
		len(deadlines) != 1 || deadlines[0].deadline.Before(workerDeadline.Add(longRequestTimeout)) {
		t.Fatalf("status %d, worker ctx err %v, worker deadline %v, HTTP deadlines %v", w.status, workerErr, workerDeadline, deadlines)
	}
}
