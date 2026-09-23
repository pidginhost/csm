package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// The CSV export takes the History tab's filters, so an operator can narrow
// it to reach entries older than the export cap.
func TestHistoryCSVHonoursTheHistoryFilters(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.High, Check: "webshell", Message: "shell one", Timestamp: now.Add(-3 * time.Minute)},
		{Severity: alert.Warning, Check: "ssh_brute", Message: "brute", Timestamp: now.Add(-2 * time.Minute)},
		{Severity: alert.High, Check: "webshell", Message: "shell two", Timestamp: now.Add(-time.Minute)},
	})

	w := httptest.NewRecorder()
	s.apiHistoryCSV(w, httptest.NewRequest(http.MethodGet, "/api/v1/history/csv?checks=webshell&search=shell", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	rows := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	if len(rows) != 3 {
		t.Fatalf("CSV rows = %d, want header + 2 webshell rows:\n%s", len(rows), w.Body.String())
	}
	if strings.Contains(w.Body.String(), "ssh_brute") {
		t.Fatalf("filtered export contains an excluded check:\n%s", w.Body.String())
	}

	w = httptest.NewRecorder()
	s.apiHistoryCSV(w, httptest.NewRequest(http.MethodGet, "/api/v1/history/csv?from=yesterday", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unreadable date: status %d, want 400", w.Code)
	}
}
