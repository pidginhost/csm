package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// seedNoisyHistory writes one in-window finding followed by more unrelated
// findings than the scan budget, all newer than it.
func seedNoisyHistory(t *testing.T, s *Server, target alert.Finding, noiseAfter time.Time) {
	t.Helper()
	s.store.AppendHistory([]alert.Finding{target})
	noise := make([]alert.Finding, 0, emailGroupsScanCap+1000)
	for i := 0; i < emailGroupsScanCap+1000; i++ {
		noise = append(noise, alert.Finding{
			Severity:  alert.Warning,
			Check:     "perf_load",
			Message:   fmt.Sprintf("load %d", i),
			Timestamp: noiseAfter.Add(time.Duration(i) * time.Millisecond),
		})
	}
	s.store.AppendHistory(noise)
}

// The scan budget bounds what is returned, not what is looked at before the
// kind and date filters: unrelated findings must not hide an email finding.
func TestEmailGroupsFindsMatchesBehindUnrelatedFindings(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()
	target := alert.Finding{Severity: alert.Critical, Check: "email_compromised_account", Message: "Compromised: user@example.com", Timestamp: now.Add(-2 * time.Hour)}
	seedNoisyHistory(t, s, target, now.Add(-time.Hour))

	w := httptest.NewRecorder()
	s.apiEmailGroups(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/groups", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var resp emailGroupsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Groups) != 1 || resp.Groups[0].Kind != "compromised_account" {
		t.Fatalf("groups = %+v, want the compromised account behind the noise", resp.Groups)
	}
	if resp.Truncated {
		t.Fatal("one match is not a truncated result")
	}
}

// A past date range is not emptied by findings that arrived after it.
func TestEmailGroupsPastRangeIgnoresLaterFindings(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	day := time.Now().Add(-72 * time.Hour).Truncate(24 * time.Hour)
	target := alert.Finding{Severity: alert.High, Check: "email_spam_outbreak", Message: "Outbreak: shop@example.com", Timestamp: day.Add(12 * time.Hour)}
	seedNoisyHistory(t, s, target, time.Now().Add(-time.Hour))

	url := "/api/v1/email/groups?from=" + day.UTC().Format(time.RFC3339) + "&to=" + day.Add(24*time.Hour).UTC().Format(time.RFC3339)
	w := httptest.NewRecorder()
	s.apiEmailGroups(w, httptest.NewRequest(http.MethodGet, url, nil))
	var resp emailGroupsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Groups) != 1 {
		t.Fatalf("groups = %+v, want the outbreak from the requested day", resp.Groups)
	}
}

func TestRelayAbuseFindsMatchesBehindUnrelatedFindings(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()
	target := alert.Finding{Severity: alert.High, Check: "email_php_relay_abuse", Message: "relay", Path: "/wp-admin/admin-ajax.php", Timestamp: now.Add(-2 * time.Hour)}
	seedNoisyHistory(t, s, target, now.Add(-time.Hour))

	w := httptest.NewRecorder()
	s.apiEmailRelayAbuse(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/relay-abuse", nil))
	var resp relayAbuseResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 1 || resp.Truncated {
		t.Fatalf("total=%d truncated=%v, want the relay finding behind the noise", resp.Total, resp.Truncated)
	}
}

func TestEmailListsReportTheirResultLimit(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now().Add(-time.Hour)
	s.store.AppendHistory([]alert.Finding{
		{Check: "email_compromised_account", Message: "Compromised: alice@example.com", Timestamp: now},
		{Check: "email_compromised_account", Message: "Compromised: bob@example.com", Timestamp: now.Add(time.Minute)},
		{Check: "email_php_relay_abuse", Message: "first relay", Timestamp: now},
		{Check: "email_php_relay_abuse", Message: "second relay", Timestamp: now.Add(time.Minute)},
	})
	t.Run("groups", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.apiEmailGroups(w, httptest.NewRequest(http.MethodGet, "/?kind=compromised_account&limit=1", nil))
		var resp emailGroupsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Groups) != 1 || !resp.Truncated {
			t.Fatalf("got %+v; want one group with truncation", resp)
		}
	})
	t.Run("relay", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.apiEmailRelayAbuse(w, httptest.NewRequest(http.MethodGet, "/?limit=1", nil))
		var resp relayAbuseResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Entries) != 1 || resp.Total != 2 || !resp.Truncated {
			t.Fatalf("got %+v; want one of two entries with truncation", resp)
		}
	})
}
