package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// scan_running reports any scan in the daemon, not only one started from
// the web UI: periodic tiers, CLI runs and scan jobs count too.
func TestAPIStatusReportsScansNotStartedFromTheUI(t *testing.T) {
	s := newTestServer(t, "token")
	for _, running := range []bool{true, false} {
		s.scanInProgress = func() bool { return running }
		w := httptest.NewRecorder()
		s.apiStatus(w, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got["scan_running"] != running {
			t.Errorf("scan_running = %v, want %v", got["scan_running"], running)
		}
	}
}
