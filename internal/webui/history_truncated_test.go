package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// truncated tells a client that more matching findings exist than the page
// returned. It was always false, even when the page left matches out.
func TestAPIHistoryReportsTruncation(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.High, Check: "webshell", Message: "one", Timestamp: now.Add(-3 * time.Minute)},
		{Severity: alert.High, Check: "webshell", Message: "two", Timestamp: now.Add(-2 * time.Minute)},
		{Severity: alert.High, Check: "webshell", Message: "three", Timestamp: now.Add(-time.Minute)},
	})
	cases := []struct {
		query string
		want  bool
	}{
		{"limit=2", true},
		{"limit=3", false},
		{"limit=2&offset=1", false},
		{"limit=2&checks=webshell", true},
		{"limit=5&checks=webshell", false},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		s.apiHistory(w, httptest.NewRequest(http.MethodGet, "/api/v1/history?"+tc.query, nil))
		var resp struct {
			Truncated *bool `json:"truncated"`
			Total     int   `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Truncated == nil || *resp.Truncated != tc.want {
			t.Errorf("%s: truncated = %v, want %v (total %d)", tc.query, resp.Truncated, tc.want, resp.Total)
		}
	}
}
