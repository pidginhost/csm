package daemon

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// Synthetic cpsrvd lines: a stale tab's page load fails on its URL security
// token, and cPanel purges the session for it.
const (
	staleTabSessionLine = `198.51.100.7 - alice [04/12/2026:07:00:05 -0000] "GET /cpsess0123456789/execute/Themes/list HTTP/1.1" 401 0 "https://example.com:2083/" "Mozilla/5.0" "-" "-" 2083`
	staleTabDeadLine    = `198.51.100.7 - - [04/12/2026:07:00:05 -0000] "GET /cpsess0123456789/execute/WebApp/list HTTP/1.1" 401 0 "https://example.com:2083/" "Mozilla/5.0" "-" "-" 2083`
	staleTabDenialLine  = `[2026-04-12 10:00:05 +0300] info [cpaneld] 198.51.100.7 PURGE alice:Sess1onNameAbCdEf tokendenied [Too many token failures (3/3)]`
	guesserSessionLine  = `203.0.113.9 - - [04/12/2026:07:00:05 -0000] "GET /cpsess0123456789/execute/Themes/list HTTP/1.1" 401 0 "-" "curl/8.0" "-" "-" 2083`
	tokenAPILine        = `198.51.100.7 - - [04/12/2026:07:00:05 -0000] "GET /execute/Themes/list HTTP/1.1" 401 0 "-" "curl/8.0" "-" "-" 2083`
)

func staleSessionAccessFindings(t *testing.T, line string) []alert.Finding {
	t.Helper()
	resetPurgeTrackerState()
	findings := parseAccessLogLineEnhanced(line, &config.Config{})
	if len(findings) != 1 || findings[0].Check != "api_auth_failure_realtime" {
		t.Fatalf("fixture line produced %v, want one api_auth_failure_realtime", findings)
	}
	return findings
}

func TestStaleSession401LateEvidenceCannotEraseExpiredFinding(t *testing.T) {
	for _, late := range []time.Duration{staleSession401Hold, staleSession401Hold + time.Second} {
		t.Run(late.String(), func(t *testing.T) {
			s := newStaleSession401s()
			now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
			_ = s.filter(staleTabSessionLine, staleSessionAccessFindings(t, staleTabSessionLine), now)
			s.observeSessionLine(staleTabDenialLine, now.Add(late))
			got := s.due(now.Add(late))
			if len(got) != 1 || got[0].SourceIP != "198.51.100.7" {
				t.Fatalf("expired finding erased by late denial: %+v", got)
			}
		})
	}
}

func TestStaleSession401LateRejectionCannotEraseExpiredFinding(t *testing.T) {
	s := newStaleSession401s()
	now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
	s.observeSessionLine(staleTabDenialLine, now)
	_ = s.filter(staleTabDeadLine, staleSessionAccessFindings(t, staleTabDeadLine), now)
	_ = s.filter(staleTabSessionLine, nil, now.Add(staleSession401Hold))
	if got := s.due(now.Add(staleSession401Hold)); len(got) != 1 {
		t.Fatalf("expired finding erased by late rejection: %+v", got)
	}
}

func TestStaleSession401RetainsRejectionThroughAnonymousHold(t *testing.T) {
	s := newStaleSession401s()
	now := time.Date(2026, 4, 12, 7, 0, 0, 0, time.UTC)
	page := strings.Replace(staleTabSessionLine, "07:00:05", "07:00:00", 1)
	anonymous := strings.Replace(staleTabDeadLine, "07:00:05", "07:00:10", 1)
	_ = s.filter(page, nil, now)
	_ = s.filter(anonymous, staleSessionAccessFindings(t, anonymous), now.Add(12*time.Second))
	if got := s.due(now.Add(19 * time.Second)); len(got) != 0 {
		t.Fatalf("anonymous finding emitted before deadline: %+v", got)
	}
	// session_log fell behind, but its evidence still arrives before the
	// anonymous request's deadline.
	s.observeSessionLine(staleTabDenialLine, now.Add(20*time.Second))
	if got := s.due(now.Add(12*time.Second + staleSession401Hold)); len(got) != 0 {
		t.Fatalf("rejection expired before anonymous hold ended: %+v", got)
	}
}

func TestStaleSession401AnonymousWaitsForOtherEdgeOfWindow(t *testing.T) {
	s := newStaleSession401s()
	now := time.Date(2026, 4, 12, 7, 0, 0, 0, time.UTC)
	anonymous := strings.Replace(staleTabDeadLine, "07:00:05", "07:00:00", 1)
	named := strings.Replace(staleTabSessionLine, "07:00:05", "07:00:10", 1)
	_ = s.filter(anonymous, staleSessionAccessFindings(t, anonymous), now)
	s.observeSessionLine(staleTabDenialLine, now.Add(5*time.Second))
	if got := s.due(now.Add(9 * time.Second)); len(got) != 0 {
		t.Fatalf("anonymous finding emitted before named evidence could arrive: %+v", got)
	}
	_ = s.filter(named, nil, now.Add(10*time.Second))
	if got := s.due(now.Add(staleSession401Hold)); len(got) != 0 {
		t.Fatalf("matching window-edge evidence did not explain anonymous request: %+v", got)
	}
}

func TestStaleSession401FlushDoesNotBlockExpiryOnFullQueue(t *testing.T) {
	d := &Daemon{
		alertCh: make(chan alert.Finding, 1), stopCh: make(chan struct{}),
		staleSession401: newStaleSession401s(),
	}
	d.alertCh <- alert.Finding{Check: "occupied"}
	queue := queuehealth.New(1, time.Minute)
	t.Cleanup(alert.RegisterQueue(d.alertCh, queue))
	now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
	_ = d.staleSession401.filter(guesserSessionLine, staleSessionAccessFindings(t, guesserSessionLine), now)
	done := make(chan struct{})
	go func() {
		d.emitDueStaleSession401(now.Add(staleSession401Hold))
		close(done)
	}()
	select {
	case <-done:
		if q := queue.Snapshot(time.Now()); q.DroppedTotal != 1 || q.Depth != 0 {
			t.Fatalf("queue saturation lost accounting: %+v", q)
		}
	case <-time.After(time.Second):
		close(d.stopCh)
		<-done
		t.Fatal("full alert queue blocked correlation expiry")
	}
}

func TestStaleSession401FloodStorageExpires(t *testing.T) {
	s := newStaleSession401s()
	now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
	findings := []alert.Finding{{Check: "api_auth_failure_realtime", SourceIP: "203.0.113.9"}}
	for i := 0; i < 4096; i++ {
		line := strings.Replace(guesserSessionLine, "0123456789", fmt.Sprintf("%010d", i), 1)
		_ = s.filter(line, findings, now)
	}
	if got := s.due(now.Add(staleSession401Hold)); len(got) != 4096 {
		t.Fatalf("reported %d flood findings, want 4096", len(got))
	}
	if len(s.held) != 0 || cap(s.held) != 0 {
		t.Fatalf("expired flood still retains held storage: len=%d cap=%d", len(s.held), cap(s.held))
	}
	for i := 0; i < 4096; i++ {
		line := strings.Replace(staleTabSessionLine, "0123456789", fmt.Sprintf("%010d", i), 1)
		_ = s.filter(line, nil, now)
	}
	s.due(now.Add(staleSessionRejectionRetention))
	if len(s.rejected) != 0 {
		t.Fatalf("expired flood retains %d rejection groups", len(s.rejected))
	}
}

func TestStaleSession401EvidenceBeforeDeadlineSurvivesDelayedFlush(t *testing.T) {
	s := newStaleSession401s()
	now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
	_ = s.filter(staleTabDeadLine, staleSessionAccessFindings(t, staleTabDeadLine), now)
	s.observeSessionLine(staleTabDenialLine, now.Add(time.Second))
	_ = s.filter(staleTabSessionLine, nil, now.Add(staleSession401Hold-time.Nanosecond))
	if got := s.due(now.Add(staleSession401Hold + time.Second)); len(got) != 0 {
		t.Fatalf("timely evidence lost when flush ran late: %+v", got)
	}
}

func TestStaleSession401ConcurrentWatchers(t *testing.T) {
	s := newStaleSession401s()
	now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
	var wg sync.WaitGroup
	for _, action := range []func(){
		func() {
			for i := 0; i < 100; i++ {
				_ = s.filter(staleTabSessionLine, nil, now)
				_ = s.filter(staleTabDeadLine, []alert.Finding{{Check: "api_auth_failure_realtime"}}, now)
			}
		},
		func() {
			for i := 0; i < 100; i++ {
				s.observeSessionLine(staleTabDenialLine, now)
			}
		},
		func() {
			for i := 0; i < 100; i++ {
				_ = s.due(now)
			}
		},
	} {
		wg.Go(action)
	}
	wg.Wait()
	if got := s.due(now.Add(staleSession401Hold)); len(got) != 0 {
		t.Fatalf("concurrent watchers failed to correlate stale tab: %+v", got)
	}
}

func BenchmarkStaleSession401Flood(b *testing.B) {
	for _, held := range []int{1000, 10000} {
		b.Run(fmt.Sprint(held), func(b *testing.B) {
			s := newStaleSession401s()
			now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
			s.observeSessionLine(staleTabDenialLine, now)
			for i := 0; i < held; i++ {
				_ = s.filter(guesserSessionLine, []alert.Finding{{Check: "api_auth_failure_realtime"}}, now)
			}
			line := strings.Replace(staleTabSessionLine, "alice", "bob", 1)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = s.filter(line, nil, now)
			}
		})
	}
}

func checksOf(findings []alert.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Check)
	}
	return out
}

// The customer-impact case: the 401s are processed before the session_log
// watcher reports the purge. None may reach the alert pipeline.
func TestStaleSession401HeldThenExplainedByLaterDenial(t *testing.T) {
	s := newStaleSession401s()
	now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)

	for _, line := range []string{staleTabSessionLine, staleTabDeadLine} {
		if got := s.filter(line, staleSessionAccessFindings(t, line), now); len(got) != 0 {
			t.Fatalf("stale-session 401 emitted before the session_log could explain it: %v", checksOf(got))
		}
	}
	s.observeSessionLine(staleTabDenialLine, now.Add(2*time.Second))

	if got := s.due(now.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("explained 401s were emitted: %v", checksOf(got))
	}
}

func TestStaleSession401DroppedWhenDenialAlreadySeen(t *testing.T) {
	s := newStaleSession401s()
	now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
	s.observeSessionLine(staleTabDenialLine, now)

	for _, line := range []string{staleTabSessionLine, staleTabDeadLine} {
		if got := s.filter(line, staleSessionAccessFindings(t, line), now.Add(time.Second)); len(got) != 0 {
			t.Fatalf("401 explained by a seen denial was emitted: %v", checksOf(got))
		}
	}
	if got := s.due(now.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("explained 401 was held and emitted: %v", checksOf(got))
	}
}

// A credential guesser has no live session here, so cPanel writes no token
// denial for it. Its finding is only delayed by the hold, then emitted
// unchanged, even while another address's stale tab is being explained.
func TestStaleSession401GuesserStillReported(t *testing.T) {
	s := newStaleSession401s()
	now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
	s.observeSessionLine(staleTabDenialLine, now)

	want := staleSessionAccessFindings(t, guesserSessionLine)
	if got := s.filter(guesserSessionLine, want, now); len(got) != 0 {
		t.Fatalf("session-URL 401 emitted before the hold: %v", checksOf(got))
	}
	if got := s.due(now.Add(staleSession401Hold - time.Second)); len(got) != 0 {
		t.Fatalf("held 401 emitted before its hold elapsed: %v", checksOf(got))
	}
	got := s.due(now.Add(staleSession401Hold))
	if len(got) != 1 || got[0].Check != "api_auth_failure_realtime" || got[0].SourceIP != "203.0.113.9" {
		t.Fatalf("guesser 401 after hold = %+v, want its api_auth_failure_realtime finding", got)
	}
	if got[0].Timestamp.IsZero() || !got[0].Timestamp.Equal(now) {
		t.Fatalf("held finding timestamp = %v, want the time the line was read (%v)", got[0].Timestamp, now)
	}
	if again := s.due(now.Add(time.Hour)); len(again) != 0 {
		t.Fatalf("held finding emitted twice: %v", checksOf(again))
	}
}

// Holding for a denial is only possible on a session URL. A token or
// password API failure has no session to purge and is reported at once.
func TestStaleSession401TokenAPIFailureNotHeld(t *testing.T) {
	s := newStaleSession401s()
	now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
	s.observeSessionLine(staleTabDenialLine, now)

	got := s.filter(tokenAPILine, staleSessionAccessFindings(t, tokenAPILine), now)
	if len(got) != 1 || got[0].Check != "api_auth_failure_realtime" {
		t.Fatalf("token API 401 = %v, want it emitted immediately", checksOf(got))
	}
}

// A denial for one account does not explain a 401 that names another
// account from the same address.
func TestStaleSession401OtherAccountStillReported(t *testing.T) {
	s := newStaleSession401s()
	now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
	s.observeSessionLine(staleTabDenialLine, now)

	bob := `198.51.100.7 - bob [04/12/2026:07:00:05 -0000] "GET /cpsess0123456789/execute/Themes/list HTTP/1.1" 401 0 "-" "Mozilla/5.0" "-" "-" 2083`
	_ = s.filter(bob, staleSessionAccessFindings(t, bob), now)
	if got := s.due(now.Add(staleSession401Hold)); len(got) != 1 {
		t.Fatalf("401 naming another account = %v, want it reported", checksOf(got))
	}
}

// Findings other than the API auth failure pass straight through.
func TestStaleSession401PassesOtherFindings(t *testing.T) {
	s := newStaleSession401s()
	other := []alert.Finding{{Check: "cpanel_file_upload_realtime", SourceIP: "198.51.100.7"}}
	got := s.filter(staleTabDeadLine, other, time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC))
	if len(got) != 1 || got[0].Check != "cpanel_file_upload_realtime" {
		t.Fatalf("unrelated finding = %v, want it passed through", checksOf(got))
	}
}

// Matching is by log time, so a stale-tab line read late because the
// access_log watcher fell behind is still explained.
func TestStaleSession401LateReadLineStillExplained(t *testing.T) {
	s := newStaleSession401s()
	seen := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
	s.observeSessionLine(staleTabDenialLine, seen)
	late := seen.Add(2 * time.Minute)
	s.due(late)

	for _, line := range []string{staleTabSessionLine, staleTabDeadLine} {
		if got := s.filter(line, staleSessionAccessFindings(t, line), late); len(got) != 0 {
			t.Fatalf("late-read stale 401 emitted: %v", checksOf(got))
		}
	}
	if got := s.due(late.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("late-read stale 401 held and emitted: %v", checksOf(got))
	}
}

// A purge explains only the page load around it. A later burst from the
// same address needs its own denial.
func TestStaleSession401OldDenialDoesNotExplainLaterBurst(t *testing.T) {
	s := newStaleSession401s()
	seen := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
	s.observeSessionLine(staleTabDenialLine, seen)

	later := `198.51.100.7 - - [04/12/2026:07:01:05 -0000] "GET /cpsess0123456789/execute/WebApp/list HTTP/1.1" 401 0 "-" "Mozilla/5.0" "-" "-" 2083`
	now := seen.Add(time.Minute)
	_ = s.filter(later, staleSessionAccessFindings(t, later), now)
	if got := s.due(now.Add(staleSession401Hold)); len(got) != 1 {
		t.Fatalf("later burst = %v, want it reported", checksOf(got))
	}
}

// Another client behind the stale tab's address does not know the tab's URL
// token, so its anonymous 401s are reported.
func TestStaleSession401SharedAddressOtherTokenReported(t *testing.T) {
	s := newStaleSession401s()
	now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
	neighbour := `198.51.100.7 - - [04/12/2026:07:00:05 -0000] "GET /cpsess9999999999/execute/Themes/list HTTP/1.1" 401 0 "-" "curl/8.0" "-" "-" 2083`

	_ = s.filter(staleTabSessionLine, staleSessionAccessFindings(t, staleTabSessionLine), now)
	_ = s.filter(neighbour, staleSessionAccessFindings(t, neighbour), now)
	s.observeSessionLine(staleTabDenialLine, now.Add(time.Second))

	got := s.due(now.Add(staleSession401Hold))
	if len(got) != 1 || got[0].Check != "api_auth_failure_realtime" {
		t.Fatalf("other-token 401 = %v, want it reported", checksOf(got))
	}
}

// The rejected request that carries the tab's token may be a page, not an
// API call, so the access_log handler reports nothing for it. It still
// counts as evidence.
func TestStaleSession401RejectionFromPageRequest(t *testing.T) {
	s := newStaleSession401s()
	now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
	page := `198.51.100.7 - alice [04/12/2026:07:00:05 -0000] "GET /cpsess0123456789/frontend/jupiter/index.html HTTP/1.1" 401 0 "-" "Mozilla/5.0" "-" "-" 2083`

	if got := s.filter(page, nil, now); len(got) != 0 {
		t.Fatalf("page request produced %v", checksOf(got))
	}
	_ = s.filter(staleTabDeadLine, staleSessionAccessFindings(t, staleTabDeadLine), now)
	s.observeSessionLine(staleTabDenialLine, now.Add(time.Second))

	if got := s.due(now.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("stale-tab 401 emitted: %v", checksOf(got))
	}
}

// Rejected requests are kept only as long as a request they explain can
// still be waiting, so a flood of them cannot grow memory without bound.
func TestStaleSession401ForgetsOldRejections(t *testing.T) {
	s := newStaleSession401s()
	now := time.Date(2026, 4, 12, 7, 0, 6, 0, time.UTC)
	_ = s.filter(staleTabSessionLine, staleSessionAccessFindings(t, staleTabSessionLine), now)
	s.observeSessionLine(staleTabDenialLine, now)

	later := now.Add(staleSessionRejectionRetention + time.Second)
	s.due(later)
	_ = s.filter(staleTabDeadLine, staleSessionAccessFindings(t, staleTabDeadLine), later)
	if got := s.due(later.Add(staleSession401Hold)); len(got) != 1 {
		t.Fatalf("401 explained by a forgotten rejection = %v, want it reported", checksOf(got))
	}
}

// End to end through the cPanel log handlers: the stale tab reaches the
// alert pipeline with nothing, the guesser's 401 arrives once its hold ends.
func TestCpanelLogHandlersHoldStaleTabAndReportGuesser(t *testing.T) {
	resetPurgeTrackerState()
	d := &Daemon{
		alertCh:         make(chan alert.Finding, 8),
		stopCh:          make(chan struct{}),
		staleSession401: newStaleSession401s(),
	}
	cfg := &config.Config{}

	for _, line := range []string{staleTabSessionLine, staleTabDeadLine, guesserSessionLine} {
		if got := d.cpanelAccessLogHandler(line, cfg); len(got) != 0 {
			t.Fatalf("access handler emitted %v for a session-URL 401", checksOf(got))
		}
	}
	if got := d.cpanelSessionLogHandler(staleTabDenialLine, cfg); len(got) != 0 {
		t.Fatalf("session handler emitted %v for a token denial", checksOf(got))
	}
	d.emitDueStaleSession401(time.Now().Add(staleSession401Hold))

	close(d.alertCh)
	var got []alert.Finding
	for f := range d.alertCh {
		got = append(got, f)
	}
	if len(got) != 1 || got[0].Check != "api_auth_failure_realtime" || got[0].SourceIP != "203.0.113.9" {
		t.Fatalf("alert pipeline received %+v, want only the guesser's finding", got)
	}
}
