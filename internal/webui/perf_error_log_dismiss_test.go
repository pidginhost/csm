package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestAPIPerformanceKeepsTierDismissalAcrossScans(t *testing.T) {
	s := newTestServer(t, "tok")
	s.samplePerf = func() *perfMetrics { return &perfMetrics{} }
	path := "/home/alice/public_html/error_log"
	warning := alert.Finding{
		Check: "perf_error_logs", Severity: alert.Warning,
		Message: "Bloated error_log: " + path, Details: "Size: 100M",
		DedupKey: "warning:" + path, Timestamp: time.Now(),
	}
	high := warning
	high.Severity, high.DedupKey, high.Details = alert.High, "critical:"+path, "Size: 2G"
	s.store.SetLatestFindings([]alert.Finding{warning})
	// Performance warnings never reach the alert dispatcher, so there is
	// deliberately no Update call before the operator dismisses this row.
	body, err := json.Marshal(map[string]string{"key": warning.Key()})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.apiDismissFinding(w, bearerRequest(http.MethodPost, "/api/v1/dismiss", body))
	if w.Code != http.StatusOK {
		t.Fatalf("dismiss status=%d body=%s", w.Code, w.Body.String())
	}
	warning.Details = "Size: 200M, growing 100M/day"
	for _, f := range []alert.Finding{warning, high, warning} {
		s.store.PurgeAndMergeFindings([]string{f.Check}, []alert.Finding{f})
		w = httptest.NewRecorder()
		s.apiPerformance(w, httptest.NewRequest(http.MethodGet, "/", nil))
		var response perfResponse
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if f.Severity == alert.Warning {
			if len(response.Findings) != 0 {
				t.Errorf("dismissed warning returned after a scan: %+v", response.Findings)
			}
		} else if len(response.Findings) != 1 || response.Findings[0].Key != high.Key() {
			t.Fatalf("dismissal hid the escalation: %+v", response.Findings)
		}
	}
}

func TestAPIPerformanceDismissalUndoRestoresVisibility(t *testing.T) {
	s := newTestServer(t, "tok")
	s.samplePerf = func() *perfMetrics { return &perfMetrics{} }
	f := alert.Finding{
		Check: "perf_error_logs", Severity: alert.Warning,
		Message:  "Bloated error_log: /home/alice/public_html/error_log",
		DedupKey: "warning:/home/alice/public_html/error_log", Timestamp: time.Now(),
	}
	s.store.SetLatestFindings([]alert.Finding{f})
	u := s.store.DismissFindingWithUndo(f.Key())
	f.Details = "Size: 200M"
	s.store.PurgeAndMergeFindings([]string{f.Check}, []alert.Finding{f})
	if !s.store.UndoDismiss(u) {
		t.Fatal("undo failed after a rescan")
	}
	w := httptest.NewRecorder()
	s.apiPerformance(w, httptest.NewRequest(http.MethodGet, "/", nil))
	var response perfResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Findings) != 1 || response.Findings[0].Key != f.Key() || response.Findings[0].Details != f.Details {
		t.Fatalf("undo did not reveal the latest observation: %+v", response.Findings)
	}
}
