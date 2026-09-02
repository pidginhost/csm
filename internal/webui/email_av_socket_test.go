package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The daemon falls back to a discovered clamd socket when the configured one is
// not answering, so mail on such a host is genuinely being scanned. This
// endpoint used to probe the configured path regardless, so the Email Security
// page reported "ClamAV: Unavailable" and an AV degraded badge over a working
// scanner -- the one reading an operator is most likely to act on.
func TestAPIEmailAVStatusFollowsTheResolvedSocket(t *testing.T) {
	const discovered = "/run/clamav/clamd.sock"

	previousResolve, previousProbe := resolveClamdSocket, clamdSocketAvailable
	resolveClamdSocket = func(configured string) (string, bool) {
		if configured == "/var/clamd" {
			return discovered, true
		}
		return configured, false
	}
	clamdSocketAvailable = func(path string) bool { return path == discovered }
	t.Cleanup(func() { resolveClamdSocket, clamdSocketAvailable = previousResolve, previousProbe })

	s := newTestServer(t, "tok")
	s.cfg.EmailAV.Enabled = true
	s.cfg.EmailAV.ClamdSocket = "/var/clamd"

	w := httptest.NewRecorder()
	s.apiEmailAVStatus(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp emailAVStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if !resp.ClamdAvailable {
		t.Error("clamd_available = false while the daemon is scanning through the discovered socket")
	}
	if resp.ClamdSocket != discovered {
		t.Errorf("clamd_socket = %q, want the socket actually in use %q", resp.ClamdSocket, discovered)
	}
}

// A configured socket that answers is reported as-is, with no discovery.
func TestAPIEmailAVStatusKeepsAWorkingConfiguredSocket(t *testing.T) {
	const configured = "/var/run/clamd.scan/clamd.sock"

	previousResolve, previousProbe := resolveClamdSocket, clamdSocketAvailable
	resolveClamdSocket = func(path string) (string, bool) { return path, false }
	clamdSocketAvailable = func(path string) bool { return path == configured }
	t.Cleanup(func() { resolveClamdSocket, clamdSocketAvailable = previousResolve, previousProbe })

	s := newTestServer(t, "tok")
	s.cfg.EmailAV.Enabled = true
	s.cfg.EmailAV.ClamdSocket = configured

	w := httptest.NewRecorder()
	s.apiEmailAVStatus(w, httptest.NewRequest("GET", "/", nil))

	var resp emailAVStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if !resp.ClamdAvailable || resp.ClamdSocket != configured {
		t.Errorf("available=%v socket=%q, want true and %q", resp.ClamdAvailable, resp.ClamdSocket, configured)
	}
}
