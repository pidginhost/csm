package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

type enrichedResponse struct {
	Findings      []enrichedFinding `json:"findings"`
	Total         int               `json:"total"`
	CriticalCount int               `json:"critical_count"`
	Version       string            `json:"version"`
}

func getEnriched(t *testing.T, s *Server, query string) enrichedResponse {
	t.Helper()
	w := httptest.NewRecorder()
	s.apiFindingsEnriched(w, httptest.NewRequest(http.MethodGet, "/api/v1/findings/enriched?"+query, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp enrichedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// The dashboard asks for ?limit=20 and shows the first critical and high
// findings. The limit returns the most severe findings, newest first, while
// the counts still cover every active finding.
func TestEnrichedFindingsLimitReturnsMostSevereFirst(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	s.store.SetLatestFindings([]alert.Finding{
		{Check: "perf_memory", Severity: alert.Warning, Message: "w", Timestamp: now},
		{Check: "webshell", Severity: alert.Critical, Message: "old critical", Timestamp: now.Add(-time.Hour)},
		{Check: "ssh_keys", Severity: alert.High, Message: "h", Timestamp: now},
		{Check: "webshell", Severity: alert.Critical, Message: "new critical", Timestamp: now},
	})

	resp := getEnriched(t, s, "limit=3")
	if len(resp.Findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(resp.Findings))
	}
	got := []string{resp.Findings[0].Message, resp.Findings[1].Message, resp.Findings[2].Message}
	if got[0] != "new critical" || got[1] != "old critical" || got[2] != "h" {
		t.Fatalf("order = %v, want most severe first, newest first within a severity", got)
	}
	if resp.Total != 4 || resp.CriticalCount != 2 {
		t.Fatalf("total=%d critical=%d, want counts over all 4", resp.Total, resp.CriticalCount)
	}
}

func TestEnrichedFindingsLimitSortsWithoutTruncating(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	s.store.SetLatestFindings([]alert.Finding{
		{Check: "perf_memory", Severity: alert.Warning, Message: "warning", Timestamp: now},
		{Check: "ip_reputation", Severity: alert.Critical, Message: "Known malicious IP accessing server: 203.0.113.7 (spamhaus)", Timestamp: now.Add(-time.Hour)},
	})
	for _, query := range []string{"limit=2", "limit=20"} {
		got := getEnriched(t, s, query)
		if len(got.Findings) != 2 || got.Findings[0].Check != "ip_reputation" || got.Total != 2 {
			t.Errorf("%s: got %+v, want both findings in severity order", query, got)
		}
	}
}

// ip_reputation rows for one address merge into one row whose message lists
// the sources; a new source changes the row and so the version.
func TestEnrichedFindingsVersionTracksIPReputation(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	s.store.SetLatestFindings([]alert.Finding{
		{Check: "ip_reputation", Severity: alert.High, Message: "Known malicious IP accessing server: 203.0.113.7 (abuseipdb)", Timestamp: now},
	})
	before := getEnriched(t, s, "fields=version").Version
	s.store.SetLatestFindings([]alert.Finding{
		{Check: "ip_reputation", Severity: alert.High, Message: "Known malicious IP accessing server: 203.0.113.7 (abuseipdb)", Timestamp: now},
		{Check: "ip_reputation", Severity: alert.High, Message: "Known malicious IP accessing server: 203.0.113.7 (spamhaus)", Timestamp: now},
	})
	after := getEnriched(t, s, "fields=version")
	if after.Total != 1 || after.Version == before {
		t.Fatalf("total=%d, version %q -> %q; want one merged row with a new version", after.Total, before, after.Version)
	}
}

// The Findings page polls only to learn whether the list changed. With
// fields=version it gets a version of the list instead of the whole list.
func TestEnrichedFindingsVersionOnly(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	s.store.SetLatestFindings([]alert.Finding{{Check: "webshell", Severity: alert.Critical, Message: "a", Timestamp: now}})

	full := getEnriched(t, s, "")
	if full.Version == "" {
		t.Fatal("full response carries no version")
	}
	v1 := getEnriched(t, s, "fields=version")
	if v1.Version != full.Version || len(v1.Findings) != 0 || v1.Total != 1 {
		t.Fatalf("version-only = %+v, want the same version, no list, total 1", v1)
	}
	if again := getEnriched(t, s, "fields=version"); again.Version != v1.Version {
		t.Fatal("version changed without a change to findings")
	}

	s.store.SetLatestFindings([]alert.Finding{
		{Check: "webshell", Severity: alert.Critical, Message: "a", Timestamp: now},
		{Check: "webshell", Severity: alert.High, Message: "b", Timestamp: now},
	})
	if v2 := getEnriched(t, s, "fields=version"); v2.Version == v1.Version {
		t.Fatal("version unchanged after a finding appeared")
	}
}
