package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/systemdrun"
)

func TestHardeningApplyRejectsBadRequests(t *testing.T) {
	s := newTestServer(t, "tok")
	cases := []struct {
		method, body string
		want         int
	}{
		{http.MethodGet, "", http.StatusMethodNotAllowed},
		{http.MethodPost, `{"category":"nope"}`, http.StatusBadRequest},
		{http.MethodPost, `{"category":`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, "/api/v1/hardening/apply", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		s.apiHardeningApply(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s %q: status %d, want %d", tc.method, tc.body, rec.Code, tc.want)
		}
	}
}

func TestHardeningApplyRefusesWhileScanRuns(t *testing.T) {
	s := newTestServer(t, "tok")
	if !s.acquireScan() {
		t.Fatal("could not take the scan lock")
	}
	defer s.releaseScan()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hardening/apply", strings.NewReader(`{"category":"ssh"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiHardeningApply(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409", rec.Code)
	}
}

func postHardeningApply(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hardening/apply", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiHardeningApply(rec, req)
	return rec
}

// The daemon's sandbox leaves the files the fixes change read-only, so the
// handler hands the request to the root worker and never applies in-process.
func TestHardeningApplyRunsTheWorkerAndRechecks(t *testing.T) {
	s := newTestServer(t, "tok")
	var got checks.HardeningApplyRequest
	calls := 0
	s.hardeningApply = func(_ context.Context, _ string, req checks.HardeningApplyRequest) ([]checks.HardeningFixResult, error) {
		calls++
		got = req
		return []checks.HardeningFixResult{{Name: "ssh_use_dns", Title: "UseDNS", Status: "applied", Message: "ok"}}, nil
	}
	rec := postHardeningApply(t, s, `{"category":"ssh","names":["ssh_use_dns"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if calls != 1 || got.Category != "ssh" || len(got.Names) != 1 || got.Names[0] != "ssh_use_dns" {
		t.Fatalf("worker calls=%d req=%+v", calls, got)
	}
	var resp struct {
		OK      bool                        `json:"ok"`
		Applied []checks.HardeningFixResult `json:"applied"`
		Results []json.RawMessage           `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || len(resp.Applied) != 1 || resp.Applied[0].Status != "applied" || len(resp.Results) == 0 {
		t.Fatalf("response = %s", rec.Body.String())
	}
}

func TestHardeningApplyRejectsBadNamesBeforeTheWorker(t *testing.T) {
	s := newTestServer(t, "tok")
	s.hardeningApply = func(context.Context, string, checks.HardeningApplyRequest) ([]checks.HardeningFixResult, error) {
		t.Fatal("worker started for an invalid request")
		return nil, nil
	}
	for _, body := range []string{`{"category":"ssh","names":["../shadow"]}`, `{"category":"ssh","extra":1}`} {
		if rec := postHardeningApply(t, s, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", body, rec.Code)
		}
	}
}

func TestHardeningApplyWithoutSystemdRunChangesNothing(t *testing.T) {
	s := newTestServer(t, "tok")
	s.hardeningApply = func(context.Context, string, checks.HardeningApplyRequest) ([]checks.HardeningFixResult, error) {
		return nil, fmt.Errorf("%w: systemd-run not found", systemdrun.ErrUnavailable)
	}
	rec := postHardeningApply(t, s, `{"category":"ssh"}`)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "nothing was changed") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHardeningApplyWorkerFailureStillRechecks(t *testing.T) {
	s := newTestServer(t, "tok")
	s.hardeningApply = func(context.Context, string, checks.HardeningApplyRequest) ([]checks.HardeningFixResult, error) {
		return nil, errors.New("hardening worker: signal: killed")
	}
	rec := postHardeningApply(t, s, `{"category":"os"}`)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "audit was re-run") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}
