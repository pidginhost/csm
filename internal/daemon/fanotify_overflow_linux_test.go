//go:build linux

package daemon

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
)

// overflowMetaBuf builds a single fanotify event buffer carrying a
// FAN_Q_OVERFLOW record: the kernel signals a lost-events overflow with
// Fd = FAN_NOFD (-1) and the FAN_Q_OVERFLOW bit set in Mask.
func overflowMetaBuf() []byte {
	buf := make([]byte, metadataSize)
	meta := (*fanotifyEventMetadata)(unsafePtr(buf))
	meta.EventLen = uint32(metadataSize)
	meta.Vers = 3
	// #nosec G115 -- FAN_NOFD is -1, fits int32.
	meta.Fd = int32(unix.FAN_NOFD)
	meta.Mask = unix.FAN_Q_OVERFLOW
	return buf
}

// DMN-11: FileMonitor must not silently swallow a kernel queue overflow.

func TestFileMonitorProcessEventsReportsQueueOverflow(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{
		cfg:          &config.Config{},
		alertCh:      ch,
		analyzerCh:   make(chan fileEvent, 1),
		reconcileSig: make(chan struct{}, 1),
	}

	fm.processEvents(overflowMetaBuf())

	if got := atomic.LoadInt64(&fm.queueOverflows); got != 1 {
		t.Fatalf("queueOverflows = %d, want 1", got)
	}

	select {
	case f := <-ch:
		if f.Check != "fanotify_kernel_overflow" {
			t.Fatalf("Check = %q, want fanotify_kernel_overflow", f.Check)
		}
		if f.Severity != alert.Warning {
			t.Fatalf("Severity = %v, want Warning", f.Severity)
		}
	default:
		t.Fatal("expected a fanotify_kernel_overflow finding after queue overflow")
	}

	// The reconcile machinery must be nudged so drop-affected directories get
	// rescanned rather than leaving storm-time writes invisible.
	select {
	case <-fm.reconcileSig:
	default:
		t.Fatal("expected a reconcile nudge after kernel overflow")
	}
}

// A plain negative-fd event that is NOT an overflow (Mask==0) must stay silent:
// the overflow detection must key on the mask, not on Fd<0 alone.
func TestFileMonitorProcessEventsNonOverflowNegativeFdSilent(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{
		cfg:          &config.Config{},
		alertCh:      ch,
		analyzerCh:   make(chan fileEvent, 1),
		reconcileSig: make(chan struct{}, 1),
	}

	buf := make([]byte, metadataSize)
	meta := (*fanotifyEventMetadata)(unsafePtr(buf))
	meta.EventLen = uint32(metadataSize)
	meta.Fd = -1
	meta.Mask = 0

	fm.processEvents(buf)

	if got := atomic.LoadInt64(&fm.queueOverflows); got != 0 {
		t.Fatalf("queueOverflows = %d, want 0 for a non-overflow negative fd", got)
	}
	select {
	case f := <-ch:
		t.Fatalf("non-overflow negative fd must not alert; got %+v", f)
	default:
	}
}

func TestFileMonitorProcessEventsRejectsTruncatedEventLength(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{
		cfg:          &config.Config{},
		alertCh:      ch,
		analyzerCh:   make(chan fileEvent, 1),
		reconcileSig: make(chan struct{}, 1),
	}

	buf := overflowMetaBuf()
	meta := (*fanotifyEventMetadata)(unsafePtr(buf))
	meta.EventLen = uint32(metadataSize + 1)

	fm.processEvents(buf)

	if got := atomic.LoadInt64(&fm.queueOverflows); got != 0 {
		t.Fatalf("queueOverflows = %d, want 0 for truncated event length", got)
	}
	select {
	case f := <-ch:
		t.Fatalf("truncated event length must not alert; got %+v", f)
	default:
	}
}

// Repeated overflows count every event but rate-limit the operator finding.
func TestFileMonitorQueueOverflowFindingRateLimited(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{
		cfg:          &config.Config{},
		alertCh:      ch,
		analyzerCh:   make(chan fileEvent, 1),
		reconcileSig: make(chan struct{}, 1),
	}

	fm.processEvents(overflowMetaBuf())
	fm.processEvents(overflowMetaBuf())

	if got := atomic.LoadInt64(&fm.queueOverflows); got != 2 {
		t.Fatalf("queueOverflows = %d, want 2 (every overflow counted)", got)
	}

	// First finding present.
	select {
	case <-ch:
	default:
		t.Fatal("expected the first overflow finding")
	}
	// Second (within the rate-limit window) suppressed.
	select {
	case f := <-ch:
		t.Fatalf("second overflow within rate-limit window should not emit; got %+v", f)
	default:
	}
}

func TestFileMonitorQueueOverflowFindingEmitsAfterQuietPeriod(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{
		cfg:                &config.Config{},
		alertCh:            ch,
		analyzerCh:         make(chan fileEvent, 1),
		reconcileSig:       make(chan struct{}, 1),
		lastOverflowReport: time.Now().Add(-2 * time.Minute),
	}

	fm.processEvents(overflowMetaBuf())

	select {
	case f := <-ch:
		if f.Check != "fanotify_kernel_overflow" {
			t.Fatalf("Check = %q, want fanotify_kernel_overflow", f.Check)
		}
	default:
		t.Fatal("expected first overflow after quiet period to emit a finding")
	}
}

func TestFileMonitorQueueOverflowMetricCountsSuppressedEvents(t *testing.T) {
	prev := fanotifyKernelOverflowTotal
	fanotifyKernelOverflowTotal = metrics.NewCounter("test_fanotify_kernel_queue_overflow_total", "")
	t.Cleanup(func() { fanotifyKernelOverflowTotal = prev })

	fm := &FileMonitor{
		cfg:          &config.Config{},
		alertCh:      make(chan alert.Finding, 4),
		analyzerCh:   make(chan fileEvent, 1),
		reconcileSig: make(chan struct{}, 1),
	}

	fm.processEvents(overflowMetaBuf())
	fm.processEvents(overflowMetaBuf())

	if got := fanotifyKernelOverflowTotal.Value(); got != 2 {
		t.Fatalf("fanotifyKernelOverflowTotal = %v, want 2", got)
	}
}

// DMN-11: SpoolWatcher runs permission events; a kernel overflow there can let
// mail through unscanned, so it must surface a Warning that says so.

func TestSpoolWatcherParseEventsReportsQueueOverflow(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{
		cfg:            &config.Config{},
		alertCh:        ch,
		permissionMode: true,
	}

	sw.parseEvents(overflowMetaBuf())

	if got := atomic.LoadInt64(&sw.queueOverflows); got != 1 {
		t.Fatalf("queueOverflows = %d, want 1", got)
	}

	select {
	case f := <-ch:
		if f.Check != "email_av_queue_overflow" {
			t.Fatalf("Check = %q, want email_av_queue_overflow", f.Check)
		}
		if f.Severity != alert.Warning {
			t.Fatalf("Severity = %v, want Warning", f.Severity)
		}
		if !strings.Contains(strings.ToLower(f.Message+" "+f.Details), "unscanned") {
			t.Fatalf("overflow finding must warn that mail may pass unscanned; got %q / %q", f.Message, f.Details)
		}
	default:
		t.Fatal("expected an email_av_queue_overflow finding after queue overflow")
	}
}

func TestSpoolWatcherQueueOverflowFindingRateLimited(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{
		cfg:            &config.Config{},
		alertCh:        ch,
		permissionMode: true,
	}

	sw.parseEvents(overflowMetaBuf())
	sw.parseEvents(overflowMetaBuf())

	if got := atomic.LoadInt64(&sw.queueOverflows); got != 2 {
		t.Fatalf("queueOverflows = %d, want 2 (every overflow counted)", got)
	}
	select {
	case <-ch:
	default:
		t.Fatal("expected the first overflow finding")
	}
	select {
	case f := <-ch:
		t.Fatalf("second overflow within rate-limit window should not emit; got %+v", f)
	default:
	}
}

func TestSpoolWatcherQueueOverflowFindingEmitsAfterQuietPeriod(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{
		cfg:            &config.Config{},
		alertCh:        ch,
		permissionMode: true,
		lastOverflowAt: time.Now().Add(-2 * time.Minute),
	}

	sw.parseEvents(overflowMetaBuf())

	select {
	case f := <-ch:
		if f.Check != "email_av_queue_overflow" {
			t.Fatalf("Check = %q, want email_av_queue_overflow", f.Check)
		}
	default:
		t.Fatal("expected first spool overflow after quiet period to emit a finding")
	}
}

func TestSpoolWatcherQueueOverflowMetricCountsSuppressedEvents(t *testing.T) {
	prev := spoolQueueOverflowTotal
	spoolQueueOverflowTotal = metrics.NewCounter("test_spool_fanotify_queue_overflow_total", "")
	t.Cleanup(func() { spoolQueueOverflowTotal = prev })

	sw := &SpoolWatcher{
		cfg:            &config.Config{},
		alertCh:        make(chan alert.Finding, 4),
		permissionMode: true,
	}

	sw.parseEvents(overflowMetaBuf())
	sw.parseEvents(overflowMetaBuf())

	if got := spoolQueueOverflowTotal.Value(); got != 2 {
		t.Fatalf("spoolQueueOverflowTotal = %v, want 2", got)
	}
}

func TestSpoolWatcherParseEventsRejectsMalformedEventLength(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{
		cfg:            &config.Config{},
		alertCh:        ch,
		permissionMode: true,
	}

	buf := overflowMetaBuf()
	meta := (*fanotifyEventMetadata)(unsafePtr(buf))
	meta.EventLen = uint32(metadataSize - 1)

	sw.parseEvents(buf)

	if got := atomic.LoadInt64(&sw.queueOverflows); got != 0 {
		t.Fatalf("queueOverflows = %d, want 0 for malformed event length", got)
	}
	select {
	case f := <-ch:
		t.Fatalf("malformed event length must not alert; got %+v", f)
	default:
	}
}

func TestSpoolWatcherParseEventsZeroEventLengthReturns(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{
		cfg:            &config.Config{},
		alertCh:        ch,
		permissionMode: true,
	}

	buf := overflowMetaBuf()
	meta := (*fanotifyEventMetadata)(unsafePtr(buf))
	meta.EventLen = 0

	done := make(chan struct{})
	go func() {
		sw.parseEvents(buf)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("parseEvents did not return for a zero-length fanotify event")
	}
	if got := atomic.LoadInt64(&sw.queueOverflows); got != 0 {
		t.Fatalf("queueOverflows = %d, want 0 for zero-length event", got)
	}
}
