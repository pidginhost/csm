package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A log that appears after startup gets its watcher later, and fanotify can
// stop. The health endpoint reports the state at request time, not the state
// when the web UI started.
func TestAPIHealthReportsWatchersStartedAfterTheUI(t *testing.T) {
	s := newTestServer(t, "token")
	watchers, fanotify := 1, false
	s.SetHealthInfo(func() bool { return fanotify }, func() int { return watchers })
	watchers, fanotify = 3, true

	w := httptest.NewRecorder()
	s.apiHealth(w, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["log_watchers"] != float64(3) || got["fanotify"] != true {
		t.Fatalf("health = %v, want the current 3 watchers and fanotify on", got)
	}
}

func TestAPIHealthWithoutDaemonReportsNothingRunning(t *testing.T) {
	s := newTestServer(t, "token")
	w := httptest.NewRecorder()
	s.apiHealth(w, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["log_watchers"] != float64(0) || got["fanotify"] != false {
		t.Fatalf("health = %v, want no watchers and fanotify off", got)
	}
}
