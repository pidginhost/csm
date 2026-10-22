package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/mailstats"
)

type emailSendersBody struct {
	Accounts    []mailstats.AccountSends `json:"accounts"`
	Total       int                      `json:"total"`
	Unresolved  int                      `json:"unresolved"`
	AbuseEvents int                      `json:"abuse_events"`
}

func serveSenders(s *Server, method, token, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v1/email/senders"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	return w
}

// The senders list names hosting accounts, so the route is admin only. It
// counts the sends of the range per account and the outbound abuse events
// the Email page lists for the same range.
func TestSendersEndpointAdminOnly(t *testing.T) {
	s, readTok := newTestServerWithReadToken(t)
	at := func(h, m int) time.Time { return time.Date(2026, 10, 20, h, m, 0, 0, time.UTC) }
	c := mailstats.New(func() time.Time { return at(13, 0) })
	for _, send := range []struct {
		at      time.Time
		account string
	}{
		{at(12, 10), "exampleacct"}, {at(12, 20), "exampleacct"}, {at(12, 30), "exampleacct"},
		{at(12, 40), "otheracct"}, {at(12, 50), ""},
		{at(10, 0), "oldacct"}, // before the range
	} {
		c.RecordSend(send.at, send.account)
	}
	s.SetMailStats(c)
	s.store.AppendHistory([]alert.Finding{
		{Check: "email_php_relay_abuse", Severity: alert.High, Path: "volume", CPUser: "exampleacct", Timestamp: at(12, 15)},
		{Check: "email_php_relay_abuse", Severity: alert.High, Path: "fanout", SourceIP: "192.0.2.10", Timestamp: at(12, 45)},
		{Check: "email_php_relay_abuse", Severity: alert.High, Path: "volume", Timestamp: at(10, 30)}, // before the range
		{Check: "email_php_relay_abuse", Severity: alert.High, Path: "volume", Timestamp: at(13, 5)},  // after it
		{Check: "waf", Severity: alert.Warning, SourceIP: "198.51.100.5", Timestamp: at(12, 30)},
	})
	const query = "?from=2026-10-20T12:00:00Z&to=2026-10-20T13:00:00Z"

	for _, tc := range []struct {
		method, token string
		want          int
	}{
		{http.MethodGet, readTok, http.StatusUnauthorized},
		{http.MethodGet, "", http.StatusUnauthorized},
		{http.MethodPost, "admin-tok", http.StatusMethodNotAllowed},
	} {
		w := serveSenders(s, tc.method, tc.token, query)
		if w.Code != tc.want {
			t.Errorf("%s token=%q: status %d, want %d: %s", tc.method, tc.token, w.Code, tc.want, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "exampleacct") {
			t.Errorf("%s token=%q: refused response names an account: %s", tc.method, tc.token, w.Body.String())
		}
	}

	w := serveSenders(s, http.MethodGet, "admin-tok", query)
	if w.Code != http.StatusOK {
		t.Fatalf("admin: status %d: %s", w.Code, w.Body.String())
	}
	var body emailSendersBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := emailSendersBody{
		Accounts:    []mailstats.AccountSends{{Account: "exampleacct", Messages: 3}, {Account: "otheracct", Messages: 1}},
		Total:       5,
		Unresolved:  1,
		AbuseEvents: 2,
	}
	if !reflect.DeepEqual(body, want) {
		t.Errorf("body = %+v, want %+v", body, want)
	}

	// The abuse count is the outbound abuse view's total for the range.
	relay := httptest.NewRecorder()
	s.apiEmailRelayAbuse(relay, httptest.NewRequest(http.MethodGet, "/api/v1/email/relay-abuse"+query, nil))
	var view relayAbuseResponse
	if err := json.Unmarshal(relay.Body.Bytes(), &view); err != nil || view.Total != body.AbuseEvents {
		t.Errorf("relay-abuse total = %d (%v), senders abuse_events = %d; want them equal", view.Total, err, body.AbuseEvents)
	}

	w = serveSenders(s, http.MethodGet, "admin-tok", "?from=yesterday")
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad from: status %d, want 400", w.Code)
	}
}

func TestSendersEndpointNoCounter(t *testing.T) {
	s := newTestServer(t, "tok")
	w := serveSenders(s, http.MethodGet, "tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"accounts":[],"total":0,"unresolved":0,"abuse_events":0}` {
		t.Errorf("body = %s, want empty counts", got)
	}
}

// The abuse count walks history, so it is memoized per query like the
// relay-abuse view it counts.
func TestSendersAbuseCountMemoized(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	const query = "from=2026-10-20T12:00:00Z&to=2026-10-20T13:00:00Z"
	from := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	key := rangeMemoKey("senders-abuse", from, from.Add(time.Hour))
	s.emailMemos.memo(key).get(s.store.HistoryMark(), func() any { return 7 })

	w := serveSenders(s, http.MethodGet, "tok", "?"+query)
	var body emailSendersBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK {
		t.Fatalf("status %d, %v: %s", w.Code, err, w.Body.String())
	}
	if body.AbuseEvents != 7 {
		t.Errorf("abuse_events = %d, want the memoized 7", body.AbuseEvents)
	}
}

// The page asks up to now, so two polls never send the same to. Requests in
// the same minute share one history walk: a finding written between them
// shows from the next minute, not before.
func TestSendersAbuseMemoSharedWithinMinute(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	relay := func(ts time.Time) alert.Finding {
		return alert.Finding{Check: "email_php_relay_abuse", Severity: alert.High, Path: "volume", Timestamp: ts}
	}
	s.store.AppendHistory([]alert.Finding{relay(at.Add(-time.Hour))})
	count := func(to string) int {
		t.Helper()
		w := serveSenders(s, http.MethodGet, "tok", "?from=2026-10-20T10:00:00Z&to="+to)
		var body emailSendersBody
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK {
			t.Fatalf("status %d, %v: %s", w.Code, err, w.Body.String())
		}
		return body.AbuseEvents
	}
	if n := count("2026-10-20T12:00:10Z"); n != 1 {
		t.Fatalf("abuse_events = %d, want 1", n)
	}
	s.store.AppendHistory([]alert.Finding{relay(at.Add(-30 * time.Minute))})
	if n := count("2026-10-20T12:00:40Z"); n != 1 {
		t.Errorf("same minute: abuse_events = %d, want the shared 1", n)
	}
	if n := count("2026-10-20T12:01:05Z"); n != 2 {
		t.Errorf("next minute: abuse_events = %d, want 2", n)
	}
}
