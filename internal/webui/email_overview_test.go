package webui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/mailstats"
)

// queueStub answers exim -bpc with count and exim -bp with listing, failing
// a probe whose reply is "fail", and counts the calls per flag. Tests change
// the replies between snapshots.
type queueStub struct {
	count, listing string
	calls          map[string]int
}

func stubQueue(t *testing.T, count, listing string) *queueStub {
	t.Helper()
	st := &queueStub{count: count, listing: listing, calls: map[string]int{}}
	withEximProbe(t,
		func(string) (string, error) { return "", exec.ErrNotFound },
		func(_ context.Context, _ string, args ...string) ([]byte, error) {
			flag := args[len(args)-1]
			st.calls[flag]++
			reply := st.listing
			if flag == "-bpc" {
				reply = st.count
			}
			if reply == "fail" {
				return nil, errors.New("exit status 1")
			}
			return []byte(reply), nil
		})
	return st
}

// queueListing is a synthetic exim -bp listing, oldest message first.
const queueListing = ` 4d  2.1K 1tQxYz-000AbC-12 <sender@example.com> *** frozen ***
          rcpt@example.net

25m  1.0K 1tQxZa-000DeF-34 <>
          other@example.net
`

func getOverview(t *testing.T, s *Server, query string) (emailOverviewResponse, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/email/overview"+query, nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp emailOverviewResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp, w.Body.String()
}

func TestEmailOverviewTotals(t *testing.T) {
	stubQueue(t, "3\n", "")
	s := newTestServer(t, "tok")
	s.cfg.EmailProtection.Antispam.Enabled = true
	s.cfg.Thresholds.MailQueueWarn, s.cfg.Thresholds.MailQueueCrit = 500, 2000
	s.cfg.Firewall = &firewall.FirewallConfig{SMTPBlock: true}
	// The counter's clock runs in a zone east of UTC; the API still sends
	// every instant in UTC.
	clock := time.Date(2026, 10, 20, 13, 0, 0, 0, time.UTC).In(time.FixedZone("east", 3*3600))
	c := mailstats.New(func() time.Time { return clock })
	c.RecordScan(time.Date(2026, 10, 20, 12, 10, 0, 0, time.UTC), antispam.Scan{OK: true, Mode: "enforce", Decision: "reject"})
	s.SetMailStats(c)

	resp, body := getOverview(t, s, "?from=2026-10-20T12:00:00Z&to=2026-10-20T13:00:00Z")

	if resp.Totals.Rejected != 1 || resp.Totals.Scanned != 1 {
		t.Errorf("totals = %+v, want one rejected scan", resp.Totals)
	}
	if len(resp.Series) != 1 || resp.Series[0].T != time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC).Unix() || resp.Series[0].Rejected != 1 {
		t.Errorf("series = %+v, want one 12:00 bucket with the reject", resp.Series)
	}
	if resp.Mode != "enforce" || !resp.SMTPRestricted {
		t.Errorf("mode = %q, smtp_restricted = %v, want enforce and true", resp.Mode, resp.SMTPRestricted)
	}
	if q := resp.Queue; q.Size != 3 || q.Unavailable || q.Warn != 500 || q.Crit != 2000 {
		t.Errorf("queue = %+v, want size 3 with warn 500 and crit 2000", q)
	}
	for _, want := range []string{`"from":"2026-10-20T12:00:00Z"`, `"to":"2026-10-20T13:00:00Z"`, `"counting_since":"2026-10-20T13:00:00Z"`} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %s: %s", want, body)
		}
	}
}

func TestEmailOverviewQueueDetailCached(t *testing.T) {
	st := stubQueue(t, "2\n", queueListing)
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

	first := queueSnapshot(t0)
	second := queueSnapshot(t0.Add(10 * time.Second))

	if st.calls["-bpc"] != 2 || st.calls["-bp"] != 1 {
		t.Fatalf("calls = %v, want -bpc twice and -bp once", st.calls)
	}
	if first.Size != 2 || first.Frozen != 1 || first.OldestAgeSeconds == nil || *first.OldestAgeSeconds != 4*86400 {
		t.Errorf("first snapshot = %+v, want size 2, one frozen, oldest 4d", first)
	}
	// The reused listing's oldest message ages with the clock.
	if second.DetailUnavailable || second.Frozen != 1 || second.OldestAgeSeconds == nil || *second.OldestAgeSeconds != 4*86400+10 {
		t.Errorf("second snapshot = %+v, want one frozen, oldest 4d plus 10 s", second)
	}
	queueSnapshot(t0.Add(time.Minute))
	if st.calls["-bp"] != 2 {
		t.Errorf("-bp ran %d times, want a new listing once the detail is a minute old", st.calls["-bp"])
	}
}

// A listing that fails, as it can by timing out on a deep queue, is retried
// no more than once a minute. The last good listing is served, aged, for ten
// minutes; after that the detail is unavailable rather than stale. Only a
// failed count makes the queue unavailable.
func TestQueueSnapshotFailedListing(t *testing.T) {
	st := stubQueue(t, "2\n", queueListing)
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	queueSnapshot(t0)

	st.listing = "fail"
	q := queueSnapshot(t0.Add(5 * time.Minute))
	if q.Unavailable || q.DetailUnavailable || q.Frozen != 1 || q.OldestAgeSeconds == nil || *q.OldestAgeSeconds != 4*86400+300 {
		t.Errorf("5 min after the last listing: %+v, want its frozen count and an oldest age 5 min older", q)
	}
	queueSnapshot(t0.Add(5*time.Minute + 30*time.Second))
	if st.calls["-bp"] != 2 {
		t.Errorf("-bp ran %d times, want a failed listing retried no sooner than a minute later", st.calls["-bp"])
	}

	q = queueSnapshot(t0.Add(11 * time.Minute))
	if st.calls["-bp"] != 3 || q.Unavailable || !q.DetailUnavailable || q.Frozen != 0 || q.OldestAgeSeconds != nil {
		t.Errorf("11 min after the last listing: %+v after %d listings, want detail unavailable with no frozen or oldest", q, st.calls["-bp"])
	}

	st.count = "fail"
	if q := queueSnapshot(t0.Add(12 * time.Minute)); !q.Unavailable {
		t.Errorf("failed count served as %+v, want unavailable", q)
	}

	stubQueue(t, "2\n", "fail")
	if q := queueSnapshot(t0); !q.DetailUnavailable || q.Frozen != 0 || q.OldestAgeSeconds != nil {
		t.Errorf("never listed: %+v, want detail unavailable", q)
	}
}

// Emptying the queue invalidates the old detail, but must not reset the
// listing throttle when new mail arrives within the same minute.
func TestQueueSnapshotEmptyQueue(t *testing.T) {
	st := stubQueue(t, "2\n", queueListing)
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	queueSnapshot(t0)

	st.count = "0\n"
	q := queueSnapshot(t0.Add(10 * time.Second))
	if q.Size != 0 || q.Unavailable || q.DetailUnavailable || q.Frozen != 0 || q.OldestAgeSeconds != nil {
		t.Errorf("empty queue served as %+v, want size 0 with no frozen or oldest", q)
	}
	if st.calls["-bp"] != 1 {
		t.Errorf("-bp ran %d times, want an empty queue left unlisted", st.calls["-bp"])
	}

	st.count, st.listing = "1\n", "10m  1.0K 1tQxZb-000GhI-56 <>\n          new@example.net\n"
	q = queueSnapshot(t0.Add(20 * time.Second))
	if st.calls["-bp"] != 1 || !q.DetailUnavailable || q.Frozen != 0 || q.OldestAgeSeconds != nil {
		t.Errorf("after 2, 0, 1: %+v after %d listings, want unknown detail until the next listing", q, st.calls["-bp"])
	}
	q = queueSnapshot(t0.Add(time.Minute))
	if st.calls["-bp"] != 2 || q.Frozen != 0 || q.OldestAgeSeconds == nil || *q.OldestAgeSeconds != 600 {
		t.Errorf("after a minute: %+v after %d listings, want a fresh listing of the new message", q, st.calls["-bp"])
	}
	if st.calls["-bpc"] != 4 {
		t.Errorf("count ran %d times, want every snapshot", st.calls["-bpc"])
	}
}

func TestEmailOverviewModeDryRunAndOff(t *testing.T) {
	stubQueue(t, "0\n", "")
	for _, tc := range []struct {
		enabled, dryRun bool
		want            string
	}{
		{true, false, "enforce"},
		{true, true, "dry-run"},
		{false, false, "off"},
		{false, true, "off"},
	} {
		s := newTestServer(t, "tok")
		s.cfg.EmailProtection.Antispam.Enabled = tc.enabled
		s.cfg.EmailProtection.Antispam.DryRun = tc.dryRun
		if resp, _ := getOverview(t, s, ""); resp.Mode != tc.want {
			t.Errorf("enabled=%v dry_run=%v: mode %q, want %q", tc.enabled, tc.dryRun, resp.Mode, tc.want)
		}
	}
}

func TestEmailOverviewNoCounter(t *testing.T) {
	stubQueue(t, "0\n", "")
	s := newTestServer(t, "tok")

	before := time.Now()
	resp, body := getOverview(t, s, "")

	if strings.Contains(body, "counting_since") {
		t.Errorf("no counter wired, yet the body names a counting start: %s", body)
	}
	if resp.Totals.Scanned != 0 || resp.Totals.Rejected != 0 || len(resp.Series) != 0 {
		t.Errorf("totals = %+v, series = %v, want zero", resp.Totals, resp.Series)
	}
	for _, want := range []string{`"gaps":[]`, `"series":[]`, `"rejects":{}`, `"temporary":{}`} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %s: %s", want, body)
		}
	}
	if resp.To.Sub(resp.From) != 24*time.Hour || resp.To.Before(before.Add(-time.Second)) || resp.To.After(time.Now()) {
		t.Errorf("range %v - %v, want the last 24 h ending now", resp.From, resp.To)
	}
	if resp.Queue.Size != 0 || resp.Queue.Unavailable {
		t.Errorf("queue = %+v, want an empty, readable queue", resp.Queue)
	}
}

func TestEmailOverviewRange(t *testing.T) {
	stubQueue(t, "0\n", "")
	s := newTestServer(t, "tok")

	// A reversed range with offsets comes back swapped and in UTC.
	_, body := getOverview(t, s, "?from=2026-10-20T16:00:00%2B03:00&to=2026-10-20T15:00:00%2B03:00")
	if !strings.Contains(body, `"from":"2026-10-20T12:00:00Z","to":"2026-10-20T13:00:00Z"`) {
		t.Errorf("reversed range not served swapped in UTC: %s", body)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/email/overview?from=yesterday", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("unreadable from: status %d, want 400", w.Code)
	}
}

func TestMailBlockCounts(t *testing.T) {
	loadedAt := time.Now()
	// The request clock runs an hour ahead of the file read, so a block
	// LoadState still holds can have lapsed by the request's now.
	now := loadedAt.Add(time.Hour)
	from, to := now.Add(-24*time.Hour), now
	dir := t.TempDir()
	writeState := func(st firewall.FirewallState) {
		t.Helper()
		raw, err := json.Marshal(st)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "firewall"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "firewall", "state.json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if got := mailBlockCounts(dir, from, to, now); got != (emailBlockCounts{}) {
		t.Errorf("no state file: %+v, want zero counts", got)
	}

	writeState(firewall.FirewallState{Blocked: []firewall.BlockedEntry{
		{IP: "203.0.113.10", Reason: "SMTP AUTH brute force", BlockedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)},
		{IP: "203.0.113.11", Reason: "Spam source", BlockedAt: now.Add(-48 * time.Hour)},
		{IP: "203.0.113.12", Reason: "mail flood", BlockedAt: now.Add(-3 * time.Hour), ExpiresAt: loadedAt.Add(-time.Minute)},
		{IP: "203.0.113.13", Reason: "smtp probe", BlockedAt: now.Add(-time.Hour), Unverified: true},
		{IP: "203.0.113.14", Reason: "WAF rule 942100", BlockedAt: now.Add(-time.Hour)},
		{IP: "2001:db8::15", Reason: "Mailer abuse", BlockedAt: now.Add(-2 * time.Hour), ExpiresAt: loadedAt.Add(30 * time.Minute)},
	}})

	if got := mailBlockCounts(dir, from, to, now); got != (emailBlockCounts{Active: 2, InRange: 1}) {
		t.Errorf("counts = %+v, want 2 active and 1 in range", got)
	}

	// A state file that cannot be read must not read as nothing blocked.
	if err := os.WriteFile(filepath.Join(dir, "firewall", "state.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := mailBlockCounts(dir, from, to, now); got != (emailBlockCounts{Unavailable: true}) {
		t.Errorf("unreadable state: %+v, want unavailable with no counts", got)
	}
}

func TestEmailOverviewReadScope(t *testing.T) {
	stubQueue(t, "0\n", "")
	s, tok := newTestServerWithReadToken(t)

	for _, tc := range []struct {
		method, token string
		want          int
	}{
		{http.MethodGet, tok, http.StatusOK},
		{http.MethodGet, "", http.StatusUnauthorized},
		{http.MethodPost, tok, http.StatusMethodNotAllowed},
	} {
		req := httptest.NewRequest(tc.method, "/api/v1/email/overview", nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s token=%q: status %d, want %d: %s", tc.method, tc.token, w.Code, tc.want, w.Body.String())
		}
	}
}
