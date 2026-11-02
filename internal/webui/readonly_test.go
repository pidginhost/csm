package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// readOnlyPrefixRouters maps table patterns whose public registration is a
// prefix router to that registration. Their contract method is "post"
// because a POST branch shares the prefix; the table binds only the GET
// handler, behind getOnly.
var readOnlyPrefixRouters = map[string]string{
	"/api/v1/scan-jobs/{id}": "/api/v1/scan-jobs/",
	"/api/v1/incidents/{id}": "/api/v1/incidents/",
}

// TestReadOnlyRoutesAreRegisteredReads proves the dispatcher table is a
// subset of the public API's GET routes: every pattern is registered on the
// public mux, as a GET route or as the GET branch of a documented prefix
// router, and nothing in the table is a write.
func TestReadOnlyRoutesAreRegisteredReads(t *testing.T) {
	registered := registeredAPIRoutes(t)
	documented := documentedAPIRoutes(t)
	s := newTestServer(t, "")
	seen := map[string]bool{}
	for _, route := range s.readOnlyRoutes() {
		if seen[route.Pattern] {
			t.Errorf("%s listed twice", route.Pattern)
		}
		seen[route.Pattern] = true
		key := route.Pattern
		if prefix, ok := readOnlyPrefixRouters[key]; ok {
			key = prefix
		}
		contract, ok := registered[key]
		if !ok {
			t.Errorf("%s is not a registered /api/v1 route", route.Pattern)
			continue
		}
		if _, prefixRouter := readOnlyPrefixRouters[route.Pattern]; prefixRouter {
			if _, ok := documented[key]; !ok {
				t.Errorf("%s: prefix router %s is not documented", route.Pattern, key)
			}
			continue
		}
		if contract.Method != "get" {
			t.Errorf("%s is registered as %s, not a read", route.Pattern, contract.Method)
		}
		if doc, ok := documented[key]; !ok || doc.Method != "get" {
			t.Errorf("%s is not documented as a GET route", route.Pattern)
		}
	}
}

func TestReadOnlyDispatcherRefusesWriteRoutes(t *testing.T) {
	s := newTestServer(t, "")
	d := s.ReadOnly()
	for _, path := range []string{
		"/api/v1/fix", "/api/v1/block-ip", "/api/v1/unblock-ip", "/api/v1/settings",
		"/api/v1/settings/alerts", "/api/v1/sessions", "/api/v1/export", "/api/v1/events",
		"/api/v1/history/csv", "/api/v1/incidents/abc/status", "/api/v1/email/queue/1a2B3c-000001-AB/delete",
		"/api/v1/geoip/batch", "/api/v1/status/../fix", "/api/", "/metrics", "/login", "",
	} {
		if d.Serves(path) {
			t.Errorf("%q is served by the read-only dispatcher", path)
		}
		status, _, _, err := d.Dispatch(context.Background(), path, nil, "127.0.0.1:1")
		if err != ErrReadOnlyRoute {
			t.Errorf("%q: status %d err %v, want ErrReadOnlyRoute", path, status, err)
		}
	}
}

func TestReadOnlyDispatcherServesStatus(t *testing.T) {
	s := newTestServer(t, "")
	d := s.ReadOnly()
	status, ctype, body, err := d.Dispatch(context.Background(), "/api/v1/health", nil, "127.0.0.1:1")
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	if !strings.HasPrefix(ctype, "application/json") {
		t.Errorf("content type %q", ctype)
	}
	var health map[string]any
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("body is not JSON: %v: %s", err, body)
	}
	if _, ok := health["uptime_seconds"]; !ok {
		t.Errorf("health lacks uptime_seconds: %s", body)
	}
}

func TestReadOnlyDispatcherPassesQueryAndPathValues(t *testing.T) {
	s := newTestServer(t, "")
	d := s.ReadOnly()
	// A required parameter that is missing answers the route's own 400.
	status, _, body, err := d.Dispatch(context.Background(), "/api/v1/finding-detail", nil, "127.0.0.1:1")
	if err != nil || status != http.StatusBadRequest {
		t.Fatalf("finding-detail without check: status %d err %v body %s", status, err, body)
	}
	q := url.Values{"check": {"nothing"}}
	status, _, body, err = d.Dispatch(context.Background(), "/api/v1/finding-detail", q, "127.0.0.1:1")
	if err != nil || status != http.StatusOK {
		t.Fatalf("finding-detail with check: status %d err %v body %s", status, err, body)
	}
	// A path value reaches the handler; an unknown incident is a 404 from it.
	status, _, _, err = d.Dispatch(context.Background(), "/api/v1/incidents/no-such-id", nil, "127.0.0.1:1")
	if err != nil || status != http.StatusNotFound {
		t.Fatalf("incident show: status %d err %v", status, err)
	}
}

func TestReadOnlyRecorderTruncates(t *testing.T) {
	rec := &readOnlyRecorder{header: http.Header{}, status: 200, limit: 8}
	if _, err := rec.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	if !rec.truncated || rec.body.String() != "01234567" {
		t.Errorf("truncated=%v body=%q", rec.truncated, rec.body.String())
	}
}
