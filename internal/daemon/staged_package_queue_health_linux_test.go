//go:build linux

package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/wpcheck"
)

func TestStagedPackageQueueHealthTracksRetryAndCapacity(t *testing.T) {
	now := time.Unix(1000, 0)
	q := newStagedPackageQueue(2)
	q.now = func() time.Time { return now.Add(15 * time.Second) }
	for i, path := range []string{"first", "second"} {
		if !q.push(stagedPackageFile{path: path, queuedAt: now.Add(time.Duration(i) * time.Second)}) {
			t.Fatalf("rejected %s within capacity", path)
		}
	}
	files := q.take(now.Add(10 * time.Second))
	if got := q.snapshot(now.Add(20 * time.Second)); got.Depth != 0 || got.InFlight != 2 || got.Capacity != 2 || got.ProcessingSeconds != 10 {
		t.Fatalf("draining batch disappeared from health: %+v", got)
	}
	for i := 0; i < 3; i++ {
		if q.push(stagedPackageFile{path: "overflow", queuedAt: now.Add(15 * time.Second)}) {
			t.Fatal("admitted new work while draining batch reserved capacity")
		}
	}
	q.requeue(files[1:], now.Add(25*time.Second))
	if got := q.snapshot(now.Add(40 * time.Second)); got.Depth != 1 || got.InFlight != 0 || got.LagSeconds != 39 || got.DroppedTotal != 3 || got.RecentDrops != 3 || got.Status != "degraded" {
		t.Fatalf("retry lost age, capacity or loss evidence: %+v", got)
	}
	if !q.push(stagedPackageFile{path: "third", queuedAt: now.Add(42 * time.Second)}) {
		t.Fatal("completed file did not release capacity")
	}
	files = q.take(now.Add(45 * time.Second))
	if len(files) != 2 || files[0].path != "second" || files[1].path != "third" {
		t.Fatalf("retry did not retain ordering and newly admitted work: %+v", files)
	}
	q.requeue(nil, now.Add(46*time.Second))
	if got := q.snapshot(now.Add(80 * time.Second)); got.Status != "ok" || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.RecentDrops != 0 {
		t.Fatalf("drained queue did not recover with loss evidence intact: %+v", got)
	}
}

func TestStagedPackageQueueHealthDetectsStalledBatch(t *testing.T) {
	now := time.Unix(1000, 0)
	q := newStagedPackageQueue(1)
	if !q.push(stagedPackageFile{path: "stalled", queuedAt: now}) {
		t.Fatal("empty queue rejected file")
	}
	q.take(now.Add(10 * time.Second))
	if got := q.snapshot(now.Add(71 * time.Second)); got.Status != "degraded" || got.Reason != "processing_lag" || got.Depth != 0 || got.InFlight != 1 || got.ProcessingSeconds != 61 {
		t.Fatalf("empty waiting queue concealed a stalled verifier: %+v", got)
	}
	q.requeue(nil, now.Add(72*time.Second))
	if got := q.snapshot(now.Add(73 * time.Second)); got.Status != "ok" || got.InFlight != 0 {
		t.Fatalf("finished verifier remained degraded: %+v", got)
	}
}

func TestStagedPackageQueueHealthKeepsRepeatedPathEventsDistinct(t *testing.T) {
	now := time.Unix(1000, 0)
	q := newStagedPackageQueue(3)
	for i := 0; i < 3; i++ {
		if !q.push(stagedPackageFile{path: "same path", queuedAt: now.Add(time.Duration(i) * time.Second)}) {
			t.Fatal("queue rejected a distinct event within capacity")
		}
	}
	files := q.take(now.Add(10 * time.Second))
	q.requeue(files[1:2], now.Add(15*time.Second))
	if got := q.snapshot(now.Add(20 * time.Second)); got.Depth != 1 || got.InFlight != 0 || got.LagSeconds != 19 || got.DroppedTotal != 0 {
		t.Fatalf("retry confused separate events for the same path: %+v", got)
	}
	q.take(now.Add(21 * time.Second))
	q.requeue(nil, now.Add(22*time.Second))
	if got := q.snapshot(now.Add(23 * time.Second)); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
		t.Fatalf("completed repeated-path events leaked accounting: %+v", got)
	}
}

func TestStagedPackageQueueHealthReportsAbandonedShutdownWork(t *testing.T) {
	now := time.Unix(1000, 0)
	q := newStagedPackageQueue(3)
	for i := 0; i < 3; i++ {
		if !q.push(stagedPackageFile{path: "pending", queuedAt: now}) {
			t.Fatal("rejected file within capacity")
		}
	}
	q.discardPending(now.Add(time.Second))
	q.discardPending(now.Add(2 * time.Second))
	if got := q.snapshot(now.Add(3 * time.Second)); got.Status != "degraded" || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.RecentDrops != 3 || q.pendingCount() != 0 {
		t.Fatalf("abandoned work was retained, lost or double-counted: %+v", got)
	}
}

func TestStagedPackageQueueHealthDatesLossAtRejection(t *testing.T) {
	now := time.Now()
	q := newStagedPackageQueue(1)
	if !q.push(stagedPackageFile{path: "full", queuedAt: now.Add(-2 * time.Minute)}) {
		t.Fatal("empty queue rejected file")
	}
	for i := 0; i < 3; i++ {
		if q.push(stagedPackageFile{path: "delayed metadata", queuedAt: now.Add(-2 * time.Minute)}) {
			t.Fatal("full queue accepted a file")
		}
	}
	if got := q.snapshot(time.Now()); got.DroppedTotal != 3 || got.RecentDrops != 3 {
		t.Fatalf("old event timestamp concealed a current rejection: %+v", got)
	}
}

func TestStagedPackageQueueHealthAppearsInMonitorStatus(t *testing.T) {
	now := time.Unix(1000, 0)
	fm := &FileMonitor{}
	if !fm.stagedPackages().push(stagedPackageFile{path: "pending", queuedAt: now}) {
		t.Fatal("empty queue rejected file")
	}
	got, ok := fm.queueStatuses(now.Add(time.Minute))["fanotify.staged_packages"]
	if !ok || got.Status != "degraded" || got.Depth != 1 || got.Capacity != stagedPackageQueueMax || got.LagSeconds != 60 {
		t.Fatalf("stalled staged queue missing from monitor health: found=%v status=%+v", ok, got)
	}
}

func TestStagedPackageVerifierHealthSurvivesRetryAndStall(t *testing.T) {
	now := time.Now()
	entered, release := make(chan struct{}), make(chan struct{})
	pending := true
	var calls int
	verifier := &fakeWPVerifier{verify: func(wpcheck.Verification) wpcheck.Verdict {
		calls++
		if pending {
			return wpcheck.VerdictPending
		}
		if calls == 3 {
			close(entered)
			<-release
		}
		return wpcheck.VerdictVerified
	}}
	fm, findings := newStagedPackageMonitor(t, verifier)
	q := fm.stagedPackages()
	for _, path := range []string{"first", "second"} {
		if !q.push(stagedPackageFile{path: path, queuedAt: now, v: wpcheck.Verification{Verdict: wpcheck.VerdictPending, Version: "1.0"}}) {
			t.Fatal("queue rejected file within capacity")
		}
	}
	fm.drainStagedPackages(now.Add(10 * time.Second))
	if got := q.snapshot(now.Add(20 * time.Second)); got.Depth != 2 || got.InFlight != 0 || got.LagSeconds != 20 {
		t.Fatalf("pending verifier reset waiting age or lost a retry: %+v", got)
	}
	verifier.mu.Lock()
	pending = false
	verifier.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fm.drainStagedPackages(now.Add(30 * time.Second))
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
		t.Fatal("queued files never reached the verifier")
	}
	got := fm.queueStatuses(time.Now().Add(61 * time.Second))["fanotify.staged_packages"]
	if got.Status != "degraded" || got.Reason != "processing_lag" || got.Depth != 0 || got.InFlight != 2 || got.ProcessingSeconds < 61 || len(findings) != 0 {
		t.Fatalf("blocked verifier was invisible or changed detection: status=%+v findings=%d", got, len(findings))
	}
	close(release)
	released = true
	<-done
	if got := q.snapshot(time.Now()); got.Status != "ok" || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || calls != 4 || len(findings) != 0 {
		t.Fatalf("verified retry failed to recover without new findings: status=%+v calls=%d findings=%d", got, calls, len(findings))
	}
}

func TestStagedPackageShutdownCountsLateAnalyzerAdmissions(t *testing.T) {
	fm := &FileMonitor{analyzerCh: make(chan fileEvent), pipeFds: [2]int{-1, -1}}
	q := fm.stagedPackages()
	fm.wg.Add(1)
	go func() {
		defer fm.wg.Done()
		for range fm.analyzerCh {
		}
		q.push(stagedPackageFile{path: "last analyzer result", queuedAt: time.Now()})
	}()
	fm.drainAndClose()
	if got := q.snapshot(time.Now()); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 || q.pendingCount() != 0 {
		t.Fatalf("analyzer appended behind shutdown accounting: %+v", got)
	}
}

func TestStagedPackageQueueHealthDoesNotWaitForPackageMetadata(t *testing.T) {
	fm := &FileMonitor{}
	q := fm.stagedPackages()
	if !q.push(stagedPackageFile{path: "waiting", queuedAt: time.Now().Add(-time.Minute)}) {
		t.Fatal("empty queue rejected file")
	}
	// Package metadata updates hold this lock while probing the filesystem.
	// A slow mount must not prevent status from exposing existing queued work.
	q.mu.Lock()
	defer q.mu.Unlock()
	done := make(chan queuehealth.Status, 1)
	go func() {
		done <- fm.queueStatuses(time.Now())["fanotify.staged_packages"]
	}()
	select {
	case got := <-done:
		if got.Status != "degraded" || got.Depth != 1 || got.Reason != "backlog_lag" {
			t.Fatalf("stalled metadata hid known queue lag: %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queue status waited for package metadata I/O")
	}
}
