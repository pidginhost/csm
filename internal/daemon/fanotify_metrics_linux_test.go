//go:build linux

package daemon

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// TestFanotifyRegisterMetricsExposesExpectedNames bypasses
// NewFileMonitor (which needs CAP_SYS_ADMIN to call fanotify_init),
// constructs a FileMonitor struct directly, and confirms that
// registerMetrics publishes the expected metric names into the
// scrape output.
//
// The previous fanotify tests in the package use the same struct-
// construction pattern for coverage. This test is not asserting
// kernel-driven drop behaviour; it asserts the metric-registration
// wiring, which is the regression class I care about here.
func TestFanotifyRegisterMetricsExposesExpectedNames(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	fm := &FileMonitor{
		cfg:        &config.Config{},
		alertCh:    ch,
		analyzerCh: make(chan fileEvent, 4000),
	}
	fm.registerMetrics()

	body := scrapeBody(t)

	for _, name := range []string{
		"csm_fanotify_events_total",
		"csm_fanotify_events_admitted_total",
		"csm_fanotify_queue_depth",
		"csm_fanotify_events_dropped_total",
		"csm_fanotify_reconcile_latency_seconds",
		"csm_realtime_content_scan_truncated_total",
	} {
		if !strings.Contains(body, "# TYPE "+name+" ") {
			t.Errorf("scrape missing TYPE line for %s:\n%s", name, body)
		}
	}
}

// TestFanotifyReconcileObservesHistogram exercises the timed section
// of reconcileDrops and verifies the histogram's _count increments.
// Catches a regression where someone removes the deferred Observe()
// from reconcileDrops.
//
// The test must point reconcileDirs at an EMPTY directory. If we
// pointed at /tmp or the cwd the reconcile loop would try to open
// real files and call fm.analyzeFile on anything interesting, against
// a FileMonitor constructed without wpCache and with a one-slot
// alertCh -- guaranteed crash or deadlock.
func TestFanotifyReconcileObservesHistogram(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	fm := &FileMonitor{
		cfg:        &config.Config{},
		alertCh:    ch,
		analyzerCh: make(chan fileEvent, 4000),
	}
	fm.registerMetrics()

	emptyDir := t.TempDir()
	fm.recordDroppedDir(filepath.Join(emptyDir, "candidate.php"))

	before := readHistogramCount(scrapeBody(t), "csm_fanotify_reconcile_latency_seconds")
	fm.reconcileDrops()
	after := readHistogramCount(scrapeBody(t), "csm_fanotify_reconcile_latency_seconds")

	if after-before != 1 {
		t.Errorf("csm_fanotify_reconcile_latency_seconds_count did not advance: before=%g after=%g", before, after)
	}
}

// readHistogramCount returns the _count sample value of an unlabelled
// histogram, 0 if not present.
func readHistogramCount(body, name string) float64 {
	target := name + "_count"
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, target+" ") {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			continue
		}
		return v
	}
	return 0
}

func TestFanotifyEventMetricsMatchAdmissionOutcomes(t *testing.T) {
	fm := eventCounterMonitor(t)
	fm.analyzerCh = make(chan fileEvent, 1)
	fm.registerMetrics()
	beforeReceived := fanotifyEventsTotal.Value()
	beforeAdmitted := fanotifyEventsAdmittedTotal.Value()
	beforeDropped := fanotifyDroppedTotal.Value()
	dir := eventFilterDir(t)
	for _, name := range []string{"first.php", "dropped.php", "filtered.rst"} {
		fm.handleEvent(openEventFD(t, filepath.Join(dir, name)), 0, FAN_CLOSE_WRITE)
	}
	fm.handleEvent(-1, 0, FAN_CLOSE_WRITE)
	event := <-fm.analyzerCh
	_ = unix.Close(event.fd)
	if got := fanotifyEventsTotal.Value() - beforeReceived; got != 4 {
		t.Errorf("received metric delta = %g, want 4", got)
	}
	if got := fanotifyEventsAdmittedTotal.Value() - beforeAdmitted; got != 1 {
		t.Errorf("admitted metric delta = %g, want 1", got)
	}
	if got := fanotifyDroppedTotal.Value() - beforeDropped; got != 1 {
		t.Errorf("dropped metric delta = %g, want 1", got)
	}
}
