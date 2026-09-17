//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/queuehealth"
)

func TestFanotifyQueueHealthTracksOverflowAndScannerFailure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "candidate.php")
	if err := os.WriteFile(path, []byte("<?php return true;"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fm := newDropperWiringTestMonitor(root, time.Minute)
	fm.analyzerCh = make(chan fileEvent, 1)
	for i := 0; i < 4; i++ {
		fd, err := unix.Dup(int(f.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		fm.handleEvent(fd, 4242, FAN_CREATE|FAN_CLOSE_WRITE)
	}
	d := &Daemon{fileMonitor: fm}
	s := d.QueueStatuses()["fanotify.analyzer"]
	if s.Depth != 1 || s.Capacity != 1 || s.DroppedTotal != 3 || s.Status != "degraded" {
		t.Fatalf("real fanotify overflow missing from provider: %+v", s)
	}
	oldAnalyzer := fileAnalyzer
	t.Cleanup(func() { fileAnalyzer = oldAnalyzer })
	var processed int
	fileAnalyzer = func(_ *FileMonitor, _ fileEvent) {
		processed++
		running := d.QueueStatuses()["fanotify.analyzer"]
		if running.Depth != 0 || running.InFlight != 1 {
			t.Errorf("worker did not claim queue item: %+v", running)
		}
		panic("test scanner failure")
	}
	close(fm.analyzerCh)
	fm.wg.Add(1)
	fm.analyzerWorker()
	s = d.QueueStatuses()["fanotify.analyzer"]
	// Three events were refused at admission; the fourth failed in the scanner.
	if processed != 1 || s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 4 {
		t.Fatalf("panic/drain lost work accounting: processed=%d status=%+v", processed, s)
	}
}

func TestFanotifyAlertLossReachesSharedQueueHealth(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	q := queuehealth.New(1, time.Minute)
	defer alert.RegisterQueue(ch, q)()
	fm := newDropperWiringTestMonitor(t.TempDir(), time.Minute)
	fm.alertCh = ch
	for i := 0; i < 4; i++ {
		fm.sendAlert(alert.Warning, "test_alert", "queue test", "")
	}
	s := q.Snapshot(time.Now())
	if s.Depth != 1 || s.DroppedTotal != 3 || s.Status != "degraded" {
		t.Fatalf("fanotify's dropped finding is missing from ingest health: %+v", s)
	}
	if got := (&Daemon{alertQueue: q}).DroppedAlerts(); got != 3 {
		t.Fatalf("CLI dropped alerts = %d, want all three producer losses", got)
	}
	f := <-ch
	alert.StartQueued(f)
	alert.FinishQueued([]alert.Finding{f})
}

func TestFanotifyKernelLossDegradesHealthWithFullAlertChannel(t *testing.T) {
	fm := newDropperWiringTestMonitor(t.TempDir(), time.Minute)
	ch := make(chan alert.Finding, 1)
	ch <- alert.Finding{Check: "test_alert"}
	fm.alertCh = ch
	for i := 0; i < 3; i++ {
		fm.processEvents(overflowMetaBuf())
	}
	d := &Daemon{fileMonitor: fm}
	queues := d.QueueStatuses()
	kernel := queues["fanotify.kernel"]
	if kernel.DroppedTotal != 3 || kernel.Status != "degraded" {
		t.Fatalf("kernel loss vanished when its finding could not be sent: %+v", kernel)
	}
	snap := health.Snapshot{StartedAt: time.Now(), StoreHealthy: true, Watchers: map[string]bool{"fanotify": true}, Queues: queues}
	if got := snap.OverallStatus(); got != "degraded" {
		t.Fatalf("overall status = %q after lost kernel events", got)
	}
	if len(ch) != 1 {
		t.Fatalf("unexpected alert channel mutation: len=%d", len(ch))
	}
}

func TestSpoolQueueHealthAccountsForPanicAndCanceledAdmission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "message-D")
	if err := os.WriteFile(path, []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}
	sw := &SpoolWatcher{scanCh: make(chan spoolEvent, 1), stopCh: make(chan struct{}), selfPID: 1}
	d := &Daemon{spoolWatcher: sw}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	sw.dispatchEvent(int32(fd), 2)
	s := d.QueueStatuses()["spool.scanner"]
	if s.Depth != 1 || s.Capacity != 1 || s.DroppedTotal != 0 {
		t.Fatalf("spool admission missing from health: %+v", s)
	}
	previousHandler := spoolEventHandler
	t.Cleanup(func() { spoolEventHandler = previousHandler })
	processed := 0
	spoolEventHandler = func(sw *SpoolWatcher, event spoolEvent) {
		defer event.finish(sw, FAN_ALLOW)
		processed++
		running := d.QueueStatuses()["spool.scanner"]
		if running.Depth != 0 || running.InFlight != 1 {
			t.Errorf("spool worker missing from health: %+v", running)
		}
		panic("test spool scanner failure")
	}
	sw.handleSpoolEventSafe(<-sw.scanCh)
	s = d.QueueStatuses()["spool.scanner"]
	if processed != 1 || s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 1 {
		t.Fatalf("spool panic leaked tracked work: processed=%d status=%+v", processed, s)
	}
	assertFDClosed(t, fd, "spool scanner panic")
	// Fill the channel, then stop: the next admission must lose its ticket
	// and close the owned descriptor without waiting for a stopped worker.
	sw.scanCh <- spoolEvent{}
	close(sw.stopCh)
	fd, err = unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	sw.dispatchEvent(int32(fd), 2)
	assertFDClosed(t, fd, "canceled spool admission")
	s = d.QueueStatuses()["spool.scanner"]
	if s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 2 {
		t.Fatalf("canceled spool admission lost accounting: %+v", s)
	}
}

func TestSpoolKernelLossDegradesHealthWithFullAlertChannel(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	ch <- alert.Finding{Check: "test_alert"}
	sw := &SpoolWatcher{alertCh: ch}
	for i := 0; i < 3; i++ {
		sw.parseEvents(overflowMetaBuf())
	}
	s := (&Daemon{spoolWatcher: sw}).QueueStatuses()["spool.kernel"]
	if s.Status != "degraded" || s.DroppedTotal != 3 {
		t.Fatalf("spool kernel loss hidden by full findings channel: %+v", s)
	}
}

func TestSpoolQueueHealthSurvivesWatcherReplacement(t *testing.T) {
	old := &SpoolWatcher{scanCh: make(chan spoolEvent, 1)}
	d := &Daemon{}
	d.setSpoolWatcher(old)
	for i := 0; i < 3; i++ {
		old.handleQueueOverflow()
	}
	d.setSpoolWatcher(&SpoolWatcher{scanCh: make(chan spoolEvent, 1)})
	s := d.QueueStatuses()["spool.kernel"]
	if s.Status != "degraded" || s.DroppedTotal != 3 {
		t.Fatalf("watcher restart erased overload evidence: %+v", s)
	}
}

func TestQueueStatusesConcurrentMonitorPublication(t *testing.T) {
	d := &Daemon{}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			d.setFileMonitor(&FileMonitor{analyzerCh: make(chan fileEvent, 3)})
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			if q, ok := d.QueueStatuses()["fanotify.analyzer"]; ok && (q.Capacity != 3 || q.Status != "ok") {
				t.Errorf("published an incomplete monitor: %+v", q)
			}
		}
	}()
	close(start)
	wg.Wait()
	if q := d.QueueStatuses()["fanotify.analyzer"]; q.Capacity != 3 || q.Status != "ok" {
		t.Fatalf("final monitor missing from health: %+v", q)
	}
}
