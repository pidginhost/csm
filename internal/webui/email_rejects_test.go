package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/mailstats"
)

type emailRejectsBody struct {
	Items    []mailstats.Reject `json:"items"`
	Class    string             `json:"class"`
	Limit    int                `json:"limit"`
	KeptDays int                `json:"kept_days"`
}

func serveRejects(s *Server, method, token, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v1/email/rejects"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	return w
}

func getRejects(t *testing.T, s *Server, query string) (emailRejectsBody, string) {
	t.Helper()
	w := serveRejects(s, http.MethodGet, "tok", query)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", query, w.Code, w.Body.String())
	}
	var body emailRejectsBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body, w.Body.String()
}

func rejectClassesOf(items []mailstats.Reject) []mailstats.Class {
	out := make([]mailstats.Class, 0, len(items))
	for _, r := range items {
		out = append(out, r.Class)
	}
	return out
}

// rejectsCounter holds a spam reject at 10:00, a sender_verify reject at
// 10:30 and a malware reject at 11:00 on 2026-10-20 UTC, recorded by a
// clock that runs in a zone east of UTC.
func rejectsCounter() *mailstats.Counter {
	east := time.FixedZone("east", 3*3600)
	clock := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC).In(east)
	c := mailstats.New(func() time.Time { return clock })
	at := func(h, m int) time.Time { return time.Date(2026, 10, 20, h, m, 0, 0, time.UTC).In(east) }
	c.RecordReject(mailstats.Reject{At: at(10, 0), Class: mailstats.ClassSpam, IP: "203.0.113.20",
		Sender: "bulk@example.net", Recipient: "user@example.com", Detail: "spam detected"})
	c.RecordReject(mailstats.Reject{At: at(10, 30), Class: mailstats.ClassSenderVerify, IP: "203.0.113.21",
		Sender: "nobody@example.net", Recipient: "user@example.com", Detail: "sender verify failed"})
	c.RecordReject(mailstats.Reject{At: at(11, 0), Class: mailstats.ClassMalware, IP: "2001:db8::22",
		Sender: "invoice@example.net", Recipient: "billing@example.com", Detail: "malware found"})
	return c
}

const rejectsRange = "from=2026-10-20T09:00:00Z&to=2026-10-20T12:00:00Z"

func TestEmailRejectsDefaultContent(t *testing.T) {
	s := newTestServer(t, "tok")
	s.SetMailStats(rejectsCounter())

	body, raw := getRejects(t, s, "?"+rejectsRange)

	if got := rejectClassesOf(body.Items); !slices.Equal(got, []mailstats.Class{mailstats.ClassMalware, mailstats.ClassSpam}) {
		t.Fatalf("classes = %v, want malware then spam", got)
	}
	if body.Class != "content" || body.Limit != 50 || body.KeptDays != 7 {
		t.Errorf("class = %q, limit = %d, kept_days = %d, want content, 50, 7", body.Class, body.Limit, body.KeptDays)
	}
	m := body.Items[0]
	if m.IP != "2001:db8::22" || m.Sender != "invoice@example.net" || m.Recipient != "billing@example.com" || m.Detail != "malware found" {
		t.Errorf("malware entry = %+v", m)
	}
	if !strings.Contains(raw, `"at":"2026-10-20T11:00:00Z"`) {
		t.Errorf("reject time not sent in UTC: %s", raw)
	}
}

// Without from and to the range is the last 24 h.
func TestEmailRejectsDefaultRange(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	c := mailstats.New(func() time.Time { return now })
	c.RecordReject(mailstats.Reject{At: now.Add(-30 * time.Hour), Class: mailstats.ClassSpam, Detail: "old"})
	c.RecordReject(mailstats.Reject{At: now.Add(-time.Hour), Class: mailstats.ClassSpam, Detail: "recent"})
	s.SetMailStats(c)

	body, _ := getRejects(t, s, "")
	if len(body.Items) != 1 || body.Items[0].Detail != "recent" {
		t.Errorf("items = %+v, want only the reject from the last 24 h", body.Items)
	}
}

func TestEmailRejectsClassFilterAndLimit(t *testing.T) {
	s := newTestServer(t, "tok")
	s.SetMailStats(rejectsCounter())

	body, _ := getRejects(t, s, "?class=all&limit=2&"+rejectsRange)
	if got := rejectClassesOf(body.Items); !slices.Equal(got, []mailstats.Class{mailstats.ClassMalware, mailstats.ClassSenderVerify}) {
		t.Errorf("class=all&limit=2: classes = %v, want the two newest", got)
	}
	if body.Class != "all" || body.Limit != 2 {
		t.Errorf("class=all&limit=2: echoed class %q, limit %d", body.Class, body.Limit)
	}

	body, _ = getRejects(t, s, "?class=sender_verify&"+rejectsRange)
	if got := rejectClassesOf(body.Items); !slices.Equal(got, []mailstats.Class{mailstats.ClassSenderVerify}) {
		t.Errorf("class=sender_verify: classes = %v", got)
	}

	// A reversed range is swapped.
	body, _ = getRejects(t, s, "?class=all&from=2026-10-20T10:45:00Z&to=2026-10-20T10:15:00Z")
	if got := rejectClassesOf(body.Items); !slices.Equal(got, []mailstats.Class{mailstats.ClassSenderVerify}) {
		t.Errorf("reversed range: classes = %v, want the 10:30 reject", got)
	}

	for _, tc := range []struct {
		limit string
		want  int
	}{{"200", 200}, {"201", 200}, {"100000", 200}, {"0", 50}, {"-3", 50}, {"x", 50}} {
		if body, _ := getRejects(t, s, "?limit="+tc.limit); body.Limit != tc.want {
			t.Errorf("limit=%s: limit %d, want %d", tc.limit, body.Limit, tc.want)
		}
	}

	for _, q := range []string{"?class=bogus%3Cscript%3E", "?class=Spam", "?class=content,spam", "?from=yesterday"} {
		w := serveRejects(s, http.MethodGet, "tok", q)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, w.Code)
		}
		if strings.Contains(w.Body.String(), "bogus") || strings.Contains(w.Body.String(), "script") {
			t.Errorf("%s: error echoes the input: %s", q, w.Body.String())
		}
	}
}

func TestEmailRejectsNoCounter(t *testing.T) {
	s := newTestServer(t, "tok")

	body, raw := getRejects(t, s, "?class=all&limit=10")
	if !strings.Contains(raw, `"items":[]`) {
		t.Errorf("body lacks an empty items list: %s", raw)
	}
	if body.Class != "all" || body.Limit != 10 || body.KeptDays != 7 {
		t.Errorf("class = %q, limit = %d, kept_days = %d, want all, 10, 7", body.Class, body.Limit, body.KeptDays)
	}
}

// The entries carry email addresses, so the route is admin only. A valid
// token outside its scope is refused with 401, as on every admin route.
func TestEmailRejectsAdminOnly(t *testing.T) {
	s, readTok := newTestServerWithReadToken(t)
	s.SetMailStats(rejectsCounter())

	for _, tc := range []struct {
		method, token string
		want          int
	}{
		{http.MethodGet, "admin-tok", http.StatusOK},
		{http.MethodGet, readTok, http.StatusUnauthorized},
		{http.MethodGet, "", http.StatusUnauthorized},
		{http.MethodPost, "admin-tok", http.StatusMethodNotAllowed},
	} {
		w := serveRejects(s, tc.method, tc.token, "?"+rejectsRange)
		if w.Code != tc.want {
			t.Errorf("%s token=%q: status %d, want %d: %s", tc.method, tc.token, w.Code, tc.want, w.Body.String())
		}
		if tc.want != http.StatusOK && strings.Contains(w.Body.String(), "example.com") {
			t.Errorf("%s token=%q: refused response carries addresses: %s", tc.method, tc.token, w.Body.String())
		}
	}
}
