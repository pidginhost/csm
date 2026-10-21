package webui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
)

var (
	testRspamdEndpoint = antispam.StatsEndpoint{Unix: true, Address: "/run/rspamd/controller.sock", RspamdUID: 990, Version: "3.9.1"}
	testRspamdStats    = antispam.RspamdStats{
		Scanned: 5000, Learned: 12, HamCount: 7, SpamCount: 5, UptimeSeconds: 3 * 86400, Version: "3.9.1",
		Actions:  map[string]int64{"no action": 4900, "reject": 41},
		TopRules: []antispam.RuleHits{{Symbol: "BAYES_SPAM", Hits: 9}, {Symbol: "RBL_EXAMPLE", Hits: 4}},
	}
)

// stubRspamdStats replaces the controller read for one test and counts the
// calls.
func stubRspamdStats(t *testing.T, fn func(context.Context, antispam.StatsEndpoint) (antispam.RspamdStats, error)) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	prev := readRspamdStats
	t.Cleanup(func() { readRspamdStats = prev })
	readRspamdStats = func(ctx context.Context, ep antispam.StatsEndpoint) (antispam.RspamdStats, error) {
		calls.Add(1)
		return fn(ctx, ep)
	}
	return &calls
}

// newRspamdTestServer has antispam enabled in enforce mode and the daemon's
// endpoint func answering ep and reason. It returns a read-scope token.
func newRspamdTestServer(t *testing.T, ep antispam.StatsEndpoint, reason string) (*Server, string) {
	t.Helper()
	s, tok := newTestServerWithReadToken(t)
	s.cfg.EmailProtection.Antispam.Enabled = true
	s.SetRspamdSource(func() (antispam.StatsEndpoint, string, bool) { return ep, reason, false })
	return s, tok
}

func getRspamd(t *testing.T, s *Server, tok string) (emailRspamdResponse, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/email/rspamd", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp emailRspamdResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp, w.Body.String()
}

func TestEmailRspamdCachesFetch(t *testing.T) {
	s, tok := newRspamdTestServer(t, testRspamdEndpoint, "")
	calls := stubRspamdStats(t, func(ctx context.Context, ep antispam.StatsEndpoint) (antispam.RspamdStats, error) {
		if ep != testRspamdEndpoint {
			t.Errorf("read endpoint %+v, want %+v", ep, testRspamdEndpoint)
		}
		if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > rspamdFetchTimeout {
			t.Errorf("fetch context deadline %v (set %v), want at most %v ahead", dl, ok, rspamdFetchTimeout)
		}
		return testRspamdStats, nil
	})

	first, body := getRspamd(t, s, tok)
	second, _ := getRspamd(t, s, tok)

	if got := calls.Load(); got != 1 {
		t.Errorf("controller read %d times for two requests, want 1", got)
	}
	if first.Status != "up" || first.Mode != "enforce" || !first.Available || first.Reason != "" || first.Version != "3.9.1" {
		t.Errorf("response = %+v, want up, enforce, available, version 3.9.1, no reason", first)
	}
	if first.Stats == nil || !reflect.DeepEqual(*first.Stats, testRspamdStats) {
		t.Errorf("stats = %+v, want %+v", first.Stats, testRspamdStats)
	}
	if first.FetchedAt.IsZero() || !second.FetchedAt.Equal(first.FetchedAt) {
		t.Errorf("fetched_at %v then %v, want one non-zero fetch time", first.FetchedAt, second.FetchedAt)
	}
	assertTimeContract(t, "/api/v1/email/rspamd", []byte(body))
	if p := nullPaths([]byte(body)); len(p) != 0 {
		t.Errorf("null values in %s: %v", body, p)
	}
}

// The cache follows the endpoint the last reconcile pass chose and lasts
// rspamdStatsTTL.
func TestEmailRspamdRefetchesAfterTTLOrNewEndpoint(t *testing.T) {
	s, tok := newRspamdTestServer(t, testRspamdEndpoint, "")
	var seen []antispam.StatsEndpoint
	calls := stubRspamdStats(t, func(_ context.Context, ep antispam.StatsEndpoint) (antispam.RspamdStats, error) {
		seen = append(seen, ep)
		return testRspamdStats, nil
	})

	getRspamd(t, s, tok)
	s.rspamdMu.Lock()
	s.rspamdCache.at = s.rspamdCache.at.Add(-rspamdStatsTTL)
	s.rspamdMu.Unlock()
	getRspamd(t, s, tok)
	if got := calls.Load(); got != 2 {
		t.Fatalf("controller read %d times across an expired cache, want 2", got)
	}

	moved := testRspamdEndpoint
	moved.Address = "/run/rspamd/other.sock"
	s.SetRspamdSource(func() (antispam.StatsEndpoint, string, bool) { return moved, "", false })
	getRspamd(t, s, tok)
	if got := calls.Load(); got != 3 || seen[2] != moved {
		t.Fatalf("after an endpoint change: %d reads, last %+v; want a third read of %+v", got, seen[len(seen)-1], moved)
	}
}

// Requests that arrive while a fetch runs wait for it instead of reading the
// controller again.
func TestEmailRspamdBurstFetchesOnce(t *testing.T) {
	s, tok := newRspamdTestServer(t, testRspamdEndpoint, "")
	entered, again := make(chan struct{}), make(chan struct{}, 16)
	var once sync.Once
	calls := stubRspamdStats(t, func(context.Context, antispam.StatsEndpoint) (antispam.RspamdStats, error) {
		first := false
		once.Do(func() { first = true; close(entered) })
		if !first {
			again <- struct{}{}
			return testRspamdStats, nil
		}
		// Give the other requests time to reach a second read, which
		// fails the test; with the fetch serialized none arrives.
		select {
		case <-again:
		case <-time.After(200 * time.Millisecond):
		}
		return testRspamdStats, nil
	})

	// getRspamd fails the test from its own goroutine; serve here and
	// decode after the burst.
	recs := make([]*httptest.ResponseRecorder, 8)
	var wg sync.WaitGroup
	serve := func(i int) {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/email/rspamd", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		recs[i] = httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(recs[i], req)
	}
	wg.Add(1)
	go serve(0)
	<-entered
	for i := 1; i < len(recs); i++ {
		wg.Add(1)
		go serve(i)
	}
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("controller read %d times for one burst, want 1", got)
	}
	for i, rec := range recs {
		var r emailRspamdResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil || rec.Code != http.StatusOK ||
			!r.Available || r.Stats == nil || r.Stats.Scanned != testRspamdStats.Scanned {
			t.Errorf("response %d: status %d %s, want the shared stats", i, rec.Code, rec.Body.String())
		}
	}
}

func TestEmailRspamdDownStillShowsMode(t *testing.T) {
	s, tok := newRspamdTestServer(t, testRspamdEndpoint, "")
	s.SetRspamdSource(func() (antispam.StatsEndpoint, string, bool) { return testRspamdEndpoint, "", true })
	s.store.PurgeAndMergeFindings(nil, []alert.Finding{{Severity: alert.Critical, Check: "antispam_rspamd_down", Message: "rspamd is down", Timestamp: time.Now()}})
	calls := stubRspamdStats(t, func(context.Context, antispam.StatsEndpoint) (antispam.RspamdStats, error) {
		return antispam.RspamdStats{}, errors.New("cannot reach /run/rspamd/controller.sock")
	})

	resp, body := getRspamd(t, s, tok)

	if resp.Status != "down" || resp.Mode != "enforce" || resp.Available || resp.Stats != nil {
		t.Errorf("response = %+v, want down, enforce, unavailable, no stats", resp)
	}
	if resp.Reason != "rspamd's controller did not answer" {
		t.Errorf("reason = %q", resp.Reason)
	}
	if resp.Version != "3.9.1" || resp.FetchedAt.IsZero() {
		t.Errorf("version %q, fetched_at %v; want the endpoint's version and the fetch time", resp.Version, resp.FetchedAt)
	}
	if strings.Contains(body, "controller.sock") {
		t.Errorf("body repeats the read error or endpoint: %s", body)
	}
	getRspamd(t, s, tok)
	if got := calls.Load(); got != 1 {
		t.Errorf("failed read retried %d times within the cache period, want 1 read", got)
	}
}

func TestEmailRspamdDismissalDoesNotRecover(t *testing.T) {
	s, tok := newRspamdTestServer(t, antispam.StatsEndpoint{}, "")
	probeDown := true
	s.SetRspamdSource(func() (antispam.StatsEndpoint, string, bool) { return antispam.StatsEndpoint{}, "", probeDown })
	down := alert.Finding{Severity: alert.Critical, Check: "antispam_rspamd_down", Message: "rspamd is down", Timestamp: time.Now()}
	s.store.PurgeAndMergeFindings(nil, []alert.Finding{down})
	if resp, _ := getRspamd(t, s, tok); resp.Status != "down" {
		t.Fatalf("before dismissal: status %q, want down", resp.Status)
	}
	if undo := s.store.DismissFindingWithUndo(down.Key()); len(undo.Removed) != 1 {
		t.Fatalf("dismissal removed %d findings, want 1", len(undo.Removed))
	}
	if resp, _ := getRspamd(t, s, tok); resp.Status != "down" {
		t.Fatalf("dismissal changed health to %q without a successful probe", resp.Status)
	}
	probeDown = false
	if resp, _ := getRspamd(t, s, tok); resp.Status != "up" {
		t.Fatalf("probe recovery left status %q, want up", resp.Status)
	}
}

func TestEmailRspamdNoEndpoint(t *testing.T) {
	const why = "rspamd's controller has no listener CSM can read without a password; add a private Unix socket (mode 0600, owned by rspamd)"
	s, tok := newRspamdTestServer(t, antispam.StatsEndpoint{Version: "3.9.1"}, why)
	calls := stubRspamdStats(t, func(context.Context, antispam.StatsEndpoint) (antispam.RspamdStats, error) {
		return testRspamdStats, nil
	})

	resp, _ := getRspamd(t, s, tok)

	if calls.Load() != 0 {
		t.Error("read the controller without an endpoint")
	}
	if resp.Status != "up" || resp.Available || resp.Stats != nil || resp.Reason != why || resp.Version != "3.9.1" || resp.FetchedAt.IsZero() {
		t.Errorf("response = %+v, want up, unavailable with the endpoint's reason and version", resp)
	}
}

// Before the first completed reconcile pass, and outside the daemon, there
// is no endpoint and no reason yet.
func TestEmailRspamdNotCheckedYet(t *testing.T) {
	calls := stubRspamdStats(t, func(context.Context, antispam.StatsEndpoint) (antispam.RspamdStats, error) {
		return testRspamdStats, nil
	})
	unset, unsetTok := newTestServerWithReadToken(t)
	unset.cfg.EmailProtection.Antispam.Enabled = true
	zero, zeroTok := newRspamdTestServer(t, antispam.StatsEndpoint{}, "")

	noFunc, _ := getRspamd(t, unset, unsetTok)
	beforeCheck, _ := getRspamd(t, zero, zeroTok)

	for name, got := range map[string]emailRspamdResponse{"no endpoint func": noFunc, "before first check": beforeCheck} {
		if got.Available || got.Reason != "rspamd's controller has not been checked yet" || got.Status != "up" {
			t.Errorf("%s: response = %+v", name, got)
		}
	}
	if calls.Load() != 0 {
		t.Error("read the controller without an endpoint")
	}
}

func TestEmailRspamdOff(t *testing.T) {
	s, tok := newRspamdTestServer(t, testRspamdEndpoint, "")
	s.cfg.EmailProtection.Antispam.Enabled = false
	s.store.PurgeAndMergeFindings(nil, []alert.Finding{{Severity: alert.Critical, Check: "antispam_rspamd_down", Message: "rspamd is down", Timestamp: time.Now()}})
	calls := stubRspamdStats(t, func(context.Context, antispam.StatsEndpoint) (antispam.RspamdStats, error) {
		return testRspamdStats, nil
	})

	resp, body := getRspamd(t, s, tok)

	if calls.Load() != 0 {
		t.Error("read the controller with antispam off")
	}
	if resp.Status != "off" || resp.Mode != "off" || resp.Available || resp.Stats != nil || resp.Reason != "antispam is off" {
		t.Errorf("response = %+v, want off, off, unavailable", resp)
	}
	assertTimeContract(t, "/api/v1/email/rspamd", []byte(body))
}

// A request that goes away mid-read must not leave its failure cached for
// everyone else.
func TestEmailRspamdCanceledRequestIsNotCached(t *testing.T) {
	s, tok := newRspamdTestServer(t, testRspamdEndpoint, "")
	calls := stubRspamdStats(t, func(ctx context.Context, _ antispam.StatsEndpoint) (antispam.RspamdStats, error) {
		if err := ctx.Err(); err != nil {
			return antispam.RspamdStats{}, err
		}
		return testRspamdStats, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/email/rspamd", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.httpSrv.Handler.ServeHTTP(httptest.NewRecorder(), req)

	resp, _ := getRspamd(t, s, tok)
	if got := calls.Load(); got != 2 || !resp.Available {
		t.Errorf("%d reads, response %+v; want a fresh read after the canceled one", got, resp)
	}
}

// writeJSON sends an empty rule list or action map as [] and {}, never null,
// so the card can read them without a null check.
func TestEmailRspamdSendsEmptyListsNotNull(t *testing.T) {
	s, tok := newRspamdTestServer(t, testRspamdEndpoint, "")
	stubRspamdStats(t, func(context.Context, antispam.StatsEndpoint) (antispam.RspamdStats, error) {
		return antispam.RspamdStats{Scanned: 3, Version: "3.9.1"}, nil
	})

	_, body := getRspamd(t, s, tok)

	if !strings.Contains(body, `"top_rules":[]`) || !strings.Contains(body, `"actions":{}`) {
		t.Errorf("body = %s, want top_rules [] and actions {}", body)
	}
}

func TestEmailRspamdReadScopeOnly(t *testing.T) {
	s, tok := newRspamdTestServer(t, antispam.StatsEndpoint{}, "")
	for _, tc := range []struct {
		method, token string
		want          int
	}{
		{http.MethodGet, tok, http.StatusOK},
		{http.MethodGet, "", http.StatusUnauthorized},
		{http.MethodPost, tok, http.StatusMethodNotAllowed},
	} {
		req := httptest.NewRequest(tc.method, "/api/v1/email/rspamd", nil)
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
