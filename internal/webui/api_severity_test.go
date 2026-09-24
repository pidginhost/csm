package webui

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// A severity filter takes the label the API sends, in any case, or the old
// 0/1/2 level scripts already use. Anything else is no filter.
func TestParseSeverityTakesLabelsAndLevels(t *testing.T) {
	for in, want := range map[string]alert.Severity{
		"CRITICAL": alert.Critical, "critical": alert.Critical, "High": alert.High, "warning": alert.Warning,
		"2": alert.Critical, "1": alert.High, "0": alert.Warning,
	} {
		got, ok := parseSeverity(in)
		if !ok || got != want {
			t.Errorf("parseSeverity(%q) = %v, %v; want %v", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "3", "-1", "info", "crit"} {
		if _, ok := parseSeverity(in); ok {
			t.Errorf("parseSeverity(%q) accepted", in)
		}
	}
}

func TestHistoryFiltersBySeverityLabel(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()
	if err := store.Global().AppendHistory([]alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "crit", Timestamp: now},
		{Severity: alert.Warning, Check: "waf_status", Message: "warn", Timestamp: now},
	}); err != nil {
		t.Fatal(err)
	}
	for _, sev := range []string{"CRITICAL", "critical", "2"} {
		w := httptest.NewRecorder()
		s.apiHistory(w, httptest.NewRequest("GET", "/api/v1/history?severity="+sev, nil))
		var got []map[string]any
		decodeItems(t, w.Body.Bytes(), &got)
		if len(got) != 1 || got[0]["message"] != "crit" || got[0]["severity"] != "CRITICAL" {
			t.Errorf("severity=%s: %v", sev, got)
		}
	}
}

func TestModSecFiltersBySeverityLevel(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()
	if err := store.Global().AppendHistory([]alert.Finding{
		modsecBlockSev("203.0.113.20", "a.example.com", "900113", alert.Warning, now.Add(-10*time.Minute)),
		modsecBlockSev("203.0.113.21", "b.example.com", "900116", alert.Critical, now.Add(-5*time.Minute)),
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.apiModSecBlocks(w, httptest.NewRequest("GET", "/?severity=2", nil))
	var resp []modsecBlockView
	decodeItems(t, w.Body.Bytes(), &resp)
	if len(resp) != 1 || resp[0].IP != "203.0.113.21" {
		t.Fatalf("severity=2 got %+v, want only the critical IP", resp)
	}
}
