//go:build linux

package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

type dropperQueueProbe func(dropperCandidate) dropperProbe

func (f dropperQueueProbe) probe(c dropperCandidate) dropperProbe { return f(c) }

func TestDropperQueueHealthCountsExhaustedProbes(t *testing.T) {
	now := time.Now()
	e, findings := newTestEngine(time.Minute)
	prober := &fakeProber{byPath: make(map[string]dropperProbe)}
	for _, path := range []string{
		"/home/alice/public_html/first.php",
		"/home/alice/public_html/second.php",
		"/home/alice/public_html/third.php",
	} {
		admitPHP(e, now.Add(-2*time.Minute), path)
		prober.byPath[path] = dropperProbe{Conclusive: false}
	}
	for i := 0; i < maxDropperProbeAttempts-1; i++ {
		e.probeStep(now, prober, now)
	}
	if e.tr.trackedCount() != 3 || prober.calls != 3*(maxDropperProbeAttempts-1) {
		t.Fatalf("retry limit was not exercised: tracked=%d probes=%d", e.tr.trackedCount(), prober.calls)
	}
	e.probeStep(now, prober, now)
	e.probeStep(now, prober, now)
	if e.tr.trackedCount() != 0 || prober.calls != 3*maxDropperProbeAttempts || len(e.attempts) != 0 || len(*findings) != 0 {
		t.Fatalf("exhausted probes were retried or manufactured findings: tracked=%d probes=%d attempts=%d findings=%+v", e.tr.trackedCount(), prober.calls, len(e.attempts), *findings)
	}
	fm := &FileMonitor{dropper: e}
	got, ok := fm.queueStatuses(time.Now())["fanotify.dropper"]
	if !ok || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.RecentDrops != 3 || got.Status != "degraded" {
		t.Fatalf("exhausted probes disappeared without health evidence: found=%v status=%+v", ok, got)
	}
}

func TestDropperRejectedRetryReleasesAttemptState(t *testing.T) {
	now := time.Now()
	e, findings := newTestEngine(time.Minute)
	e.tr.maxTracked = 1
	admitPHP(e, now.Add(-2*time.Minute), "/home/alice/public_html/original.php")
	prober := dropperQueueProbe(func(c dropperCandidate) dropperProbe {
		incoming := c
		incoming.Path = "/home/alice/public_html/new.php"
		incoming.Inode++
		incoming.Observed = now
		if !e.tr.Observe(incoming) {
			t.Fatal("concurrent observation did not consume the available slot")
		}
		return dropperProbe{Conclusive: false}
	})
	e.probeStep(now, prober, now)
	if e.tr.trackedCount() != 1 || e.tr.overflowDropped() != 1 || len(*findings) != 0 {
		t.Fatalf("rejected retry changed retained work or emitted a verdict: tracked=%d lost=%d findings=%+v", e.tr.trackedCount(), e.tr.overflowDropped(), *findings)
	}
	if len(e.attempts) != 0 {
		t.Fatalf("rejected retry retained %d unreachable attempt records", len(e.attempts))
	}
}

func TestDropperQueueHealthRefreshPreservesRetryLimit(t *testing.T) {
	now := time.Now()
	e, findings := newTestEngine(time.Minute)
	c := freshDropperCandidate(now.Add(-2 * time.Minute))
	c.BirthKnown = false
	if !e.tr.Observe(c) {
		t.Fatal("initial observation was refused")
	}
	prober := &fakeProber{byPath: map[string]dropperProbe{c.Path: {Conclusive: false}}}
	e.probeStep(now, prober, now)
	c.Birth, c.BirthKnown = c.Observed, true
	if !e.tr.Refresh(c) {
		t.Fatal("close-write did not strengthen the waiting identity")
	}
	for i := 0; i < maxDropperProbeAttempts+1; i++ {
		e.probeStep(now, prober, now)
	}
	if prober.calls != maxDropperProbeAttempts || len(e.attempts) != 0 || e.tr.trackedCount() != 0 || len(*findings) != 0 {
		t.Fatalf("identity refresh reset retries or stranded accounting: probes=%d attempts=%d tracked=%d findings=%+v", prober.calls, len(e.attempts), e.tr.trackedCount(), *findings)
	}
	got := (&FileMonitor{dropper: e}).queueStatuses(time.Now())["fanotify.dropper"]
	if got.DroppedTotal != 1 || got.Depth != 0 || got.InFlight != 0 {
		t.Fatalf("exhausted refreshed candidate lost health evidence: %+v", got)
	}
}

func TestDropperHeldFindingsStayBounded(t *testing.T) {
	now := time.Now()
	tr := newDropperTracker(time.Minute)
	for i := 0; i < dropperMaxTracked+1; i++ {
		c := freshDropperCandidate(now)
		c.Path = fmt.Sprintf("/home/alice/public_html/candidate-%d.php", i)
		c.Docroot = "/home/alice/public_html"
		tr.HoldGone(c, dropperSuspect, now)
	}
	if len(tr.pending) != dropperMaxTracked {
		t.Fatalf("held queue contains %d entries, want the %d-entry bound", len(tr.pending), dropperMaxTracked)
	}
	if tr.pending[0].Cand.Path != "/home/alice/public_html/candidate-0.php" {
		t.Fatalf("held queue evicted older evidence: first=%s", tr.pending[0].Cand.Path)
	}
	_, held := tr.queueStatuses(time.Now())
	if held.Depth != dropperMaxTracked || held.Capacity != dropperMaxTracked || held.InFlight != 0 || held.DroppedTotal != 1 || held.RecentDrops != 1 {
		t.Fatalf("held rejection lost its capacity or current loss evidence: %+v", held)
	}
	groups := tr.FlushDue(now.Add(dropperGraceWindow + time.Second))
	if len(groups) != 1 || len(groups[0].Items) != dropperMaxTracked {
		t.Fatalf("bounded held evidence was lost during aggregation: groups=%d", len(groups))
	}
}

func TestDropperQueueHealthMergesRetryWithNewObservation(t *testing.T) {
	now := time.Now()
	e, _ := newTestEngine(time.Minute)
	observed := now.Add(-2 * time.Minute)
	admitPHP(e, observed, "/home/alice/public_html/same.php")
	prober := dropperQueueProbe(func(c dropperCandidate) dropperProbe {
		incoming := c
		incoming.Observed, incoming.Size, incoming.ContentSuspicious = now, 999, true
		if !e.tr.Observe(incoming) {
			t.Fatal("new observation was not admitted during the probe")
		}
		return dropperProbe{Conclusive: false}
	})
	e.probeStep(now, prober, now)
	fm := &FileMonitor{dropper: e}
	got, ok := fm.queueStatuses(now)["fanotify.dropper"]
	if !ok || got.Depth != 1 || got.InFlight != 0 || got.LagSeconds != 60 || got.DroppedTotal != 0 {
		t.Fatalf("merged retry reset overdue age or leaked a ticket: found=%v status=%+v", ok, got)
	}
	candidates := e.tr.Due(now)
	if len(candidates) != 1 || !candidates[0].Observed.Equal(observed) || candidates[0].Size != 999 || !candidates[0].ContentSuspicious {
		t.Fatalf("merged retry lost earliest observation or newer evidence: %+v", candidates)
	}
}

func TestDropperQueueHealthShowsBlockedProbe(t *testing.T) {
	now := time.Now()
	e, _ := newTestEngine(time.Minute)
	admitPHP(e, now.Add(-2*time.Minute), "/home/alice/public_html/probe.php")
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	prober := dropperQueueProbe(func(dropperCandidate) dropperProbe {
		close(entered)
		<-release
		return dropperProbe{Conclusive: false}
	})
	go func() {
		defer close(done)
		e.probeStep(now, prober, now)
	}()
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
		<-done
	})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("candidate did not reach the probe")
	}
	fm := &FileMonitor{dropper: e}
	got, ok := fm.queueStatuses(now.Add(61 * time.Second))["fanotify.dropper"]
	if !ok || got.Status != "degraded" || got.Reason != "processing_lag" || got.Depth != 0 || got.InFlight != 1 || got.ProcessingSeconds != 61 {
		t.Fatalf("detached candidate concealed blocked probe: found=%v status=%+v", ok, got)
	}
	close(release)
	released = true
	<-done
	if got := fm.queueStatuses(time.Now())["fanotify.dropper"]; got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 0 {
		t.Fatalf("unblocked probe did not return the retry: %+v", got)
	}
}

func TestDropperQueueHealthAccountsForHeldFindingLifecycle(t *testing.T) {
	for _, outcome := range []string{"emitted", "suppressed", "shutdown"} {
		t.Run(outcome, func(t *testing.T) {
			now := time.Now()
			e, findings := newTestEngine(time.Minute)
			admitPHP(e, now.Add(-2*time.Minute), "/home/alice/public_html/held.php")
			e.probeStep(now, &fakeProber{}, now)
			fm := &FileMonitor{dropper: e, analyzerCh: make(chan fileEvent), pipeFds: [2]int{-1, -1}}
			got, ok := fm.queueStatuses(now)["fanotify.dropper_findings"]
			if !ok || got.Status != "ok" || got.Depth != 1 || got.InFlight != 0 || got.LagSeconds != 0 || len(*findings) != 0 {
				t.Fatalf("grace-period work was missing or treated as late: found=%v status=%+v findings=%+v", ok, got, *findings)
			}
			wantFindings, wantDropped := 0, uint64(0)
			switch outcome {
			case "emitted":
				wantFindings = 1
			case "suppressed":
				e.ignorePath = func(string) bool { return true }
			case "shutdown":
				fm.drainAndClose()
				wantDropped = 1
			}
			if outcome != "shutdown" {
				e.probeStep(now.Add(dropperGraceWindow), &fakeProber{}, now.Add(dropperGraceWindow))
			}
			statuses := fm.queueStatuses(time.Now())
			if got := statuses["fanotify.dropper_findings"]; got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != wantDropped || len(*findings) != wantFindings {
				t.Fatalf("held outcome %s lost accounting: status=%+v findings=%+v", outcome, got, *findings)
			}
			if got := statuses["fanotify.dropper"]; got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
				t.Fatalf("completed probe leaked into candidate health: %+v", got)
			}
		})
	}
}

func TestDropperQueueHealthShutdownIncludesLateObservations(t *testing.T) {
	now := time.Now()
	e, _ := newTestEngine(time.Minute)
	admitPHP(e, now, "/home/alice/public_html/early.php")
	fm := &FileMonitor{dropper: e, analyzerCh: make(chan fileEvent), pipeFds: [2]int{-1, -1}}
	fm.wg.Add(1)
	go func() {
		defer fm.wg.Done()
		for range fm.analyzerCh {
		}
		admitPHP(e, now, "/home/alice/public_html/late.php")
	}()
	fm.drainAndClose()
	fm.drainAndClose()
	got := fm.queueStatuses(time.Now())["fanotify.dropper"]
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 2 || e.tr.trackedCount() != 0 || len(e.attempts) != 0 {
		t.Fatalf("shutdown lost or double-counted late analyzer work: status=%+v tracked=%d attempts=%d", got, e.tr.trackedCount(), len(e.attempts))
	}
}

func TestDropperQueueHealthTracksPartlySuppressedEmission(t *testing.T) {
	now := time.Now()
	e, findings := newTestEngine(time.Minute)
	for i := 0; i < 9; i++ {
		admitPHP(e, now.Add(-2*time.Minute), fmt.Sprintf("/home/alice/public_html/held-%d.php", i))
	}
	e.probeStep(now, &fakeProber{}, now)
	e.ignorePath = func(path string) bool {
		return path == "/home/alice/public_html/held-0.php" || path == "/home/alice/public_html/held-1.php"
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	oldEmit, calls := e.emit, 0
	e.emit = func(sev alert.Severity, check, msg, details, path string) {
		calls++
		if calls == 1 {
			close(entered)
			<-release
		}
		oldEmit(sev, check, msg, details, path)
	}
	flush := now.Add(dropperGraceWindow)
	go func() {
		defer close(done)
		e.probeStep(flush, &fakeProber{}, flush)
	}()
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
		<-done
	})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("held batch was not emitted")
	}
	fm := &FileMonitor{dropper: e}
	got := fm.queueStatuses(flush.Add(61 * time.Second))["fanotify.dropper_findings"]
	if got.Depth != 0 || got.InFlight != 9 || got.Reason != "processing_lag" || got.ProcessingSeconds != 61 {
		t.Fatalf("blocked partial emission concealed its original batch: %+v", got)
	}
	close(release)
	released = true
	<-done
	got = fm.queueStatuses(time.Now())["fanotify.dropper_findings"]
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || len(*findings) != 7 {
		t.Fatalf("suppression or emission leaked accounting: status=%+v findings=%+v", got, *findings)
	}
	for _, f := range *findings {
		if f.sev != alert.Critical {
			t.Fatalf("suppressed members changed remaining severity: %+v", f)
		}
	}
}
