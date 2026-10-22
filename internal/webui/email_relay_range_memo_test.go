package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Polls can share a history snapshot, but their exact bounds must still
// filter findings and describe the response, including fractional seconds.
func TestEmailRelayMemoPreservesExactRanges(t *testing.T) {
	at := time.Date(2026, 10, 20, 12, 0, 20, 500000000, time.UTC)
	minute := at.Truncate(time.Minute)
	for _, endpoint := range []string{"relay-abuse", "senders"} {
		t.Run(endpoint, func(t *testing.T) {
			for _, bound := range []string{"from", "to"} {
				t.Run(bound, func(t *testing.T) {
					s := newTestServerWithBbolt(t, "tok")
					s.store.AppendHistory([]alert.Finding{{Check: "email_php_relay_abuse", Severity: alert.High, Path: "volume", Timestamp: at}})
					if bound == "from" {
						assertEmailRelayRange(t, s, endpoint, minute, minute.Add(time.Minute), 1, false)
						assertEmailRelayRange(t, s, endpoint, at, minute.Add(time.Minute), 1, false)
						assertEmailRelayRange(t, s, endpoint, at.Add(time.Nanosecond), minute.Add(time.Minute), 0, false)
					} else {
						assertEmailRelayRange(t, s, endpoint, minute.Add(-time.Minute), at, 0, false)
						assertEmailRelayRange(t, s, endpoint, minute.Add(-time.Minute), at.Add(time.Nanosecond), 1, false)
					}
				})
			}
		})
	}
}

// A minute-wide cache can reach the history cap entirely on findings after
// the requested upper bound. Those rows must not hide an earlier match.
func TestEmailRelayMemoBoundaryOverflow(t *testing.T) {
	minute := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	rows := make([]alert.Finding, 0, emailGroupsScanCap+2)
	rows = append(rows, alert.Finding{Check: "email_php_relay_abuse", Severity: alert.High, Path: "volume", Timestamp: minute.Add(-30 * time.Second)})
	for i := 0; i <= emailGroupsScanCap; i++ {
		rows = append(rows, alert.Finding{Check: "email_php_relay_abuse", Severity: alert.High, Path: "fanout", Timestamp: minute.Add(50*time.Second + time.Duration(i)*time.Nanosecond)})
	}
	for _, endpoint := range []string{"relay-abuse", "senders"} {
		t.Run(endpoint, func(t *testing.T) {
			s := newTestServerWithBbolt(t, "tok")
			s.store.AppendHistory(rows)
			from := minute.Add(-time.Minute)
			assertEmailRelayRange(t, s, endpoint, from, minute.Add(59*time.Second), emailGroupsScanCap, true)
			assertEmailRelayRange(t, s, endpoint, from, minute.Add(20*time.Second), 1, false)
		})
	}
}

func assertEmailRelayRange(t *testing.T, s *Server, endpoint string, from, to time.Time, total int, truncated bool) {
	t.Helper()
	query := "?from=" + from.Format(time.RFC3339Nano) + "&to=" + to.Format(time.RFC3339Nano)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/email/"+endpoint+query, nil)
	if endpoint == "senders" {
		s.apiEmailSenders(w, r)
	} else {
		s.apiEmailRelayAbuse(w, r)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if endpoint == "senders" {
		var response emailSendersBody
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.AbuseEvents != total {
			t.Errorf("range %v .. %v: abuse_events = %d, want %d", from, to, response.AbuseEvents, total)
		}
		return
	}
	var response relayAbuseResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.From.Equal(from) || !response.To.Equal(to) {
		t.Errorf("response range = %v .. %v, want %v .. %v", response.From, response.To, from, to)
	}
	if response.Total != total || response.Truncated != truncated || len(response.Entries) != min(total, relayAbuseDefaultLimit) {
		t.Errorf("total/truncated/items = %d/%v/%d, want %d/%v/%d", response.Total, response.Truncated, len(response.Entries), total, truncated, min(total, relayAbuseDefaultLimit))
	}
	for _, entry := range response.Entries {
		if entry.DetectedAt.Before(from) || !entry.DetectedAt.Before(to) {
			t.Errorf("entry at %v is outside %v .. %v", entry.DetectedAt, from, to)
		}
	}
}
