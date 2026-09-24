package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A date filter the server cannot read is an error. Ignoring it showed an
// unfiltered or empty result as if it matched the requested range.
func TestHistoryRangeEndpointsRejectUnreadableDates(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	endpoints := map[string]http.HandlerFunc{
		"/api/v1/history":           s.apiHistory,
		"/api/v1/email/groups":      s.apiEmailGroups,
		"/api/v1/email/relay-abuse": s.apiEmailRelayAbuse,
	}
	for path, h := range endpoints {
		for _, q := range []string{"from=yesterday", "to=2026-02-30"} {
			w := httptest.NewRecorder()
			h(w, httptest.NewRequest(http.MethodGet, path+"?"+q, nil))
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s?%s: status %d, want 400", path, q, w.Code)
			}
		}
	}
}

// The end of a range given as an instant is exclusive, the same as on the
// history endpoint, so one day in the operator's zone is [start, next start).
func TestEmailGroupsInstantRangeEndIsExclusive(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	start := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	end := start.Add(24 * time.Hour)
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.High, Check: "email_spam_outbreak", Message: "Outbreak: in@example.com", Timestamp: end.Add(-time.Second)},
		{Severity: alert.High, Check: "email_compromised_account", Message: "Compromised: out@example.com", Timestamp: end},
	})
	url := "/api/v1/email/groups?from=" + start.UTC().Format(time.RFC3339) + "&to=" + end.UTC().Format(time.RFC3339)
	w := httptest.NewRecorder()
	s.apiEmailGroups(w, httptest.NewRequest(http.MethodGet, url, nil))
	var resp emailGroupsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Groups) != 1 || resp.Groups[0].Kind != "spam_outbreak" {
		t.Fatalf("groups = %+v, want only the finding before the end instant", resp.Groups)
	}
}
