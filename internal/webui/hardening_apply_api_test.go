package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
