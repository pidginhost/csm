//go:build linux

package daemon

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/yara"
)

// A realtime scan failure used to be reported as "yara_scan_incomplete",
// the same name and severity the scheduled deep scan uses for its coverage
// report. On a live host that report fires around thirteen times a day
// forever, for archives past the scan size limit, so the one finding that
// means "a file changed while malware scanning was not running" was
// indistinguishable from routine backlog. Anyone filtering the chronic one
// lost the outage.
func TestRealtimeYARAScanErrorHasItsOwnCheck(t *testing.T) {
	alerts := make(chan alert.Finding, 1)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}

	fm.reportYARAScanError("/home/alice/public_html/x.php", errors.New("worker unavailable"))

	select {
	case finding := <-alerts:
		if finding.Check != "yara_realtime_scan_error" {
			t.Fatalf("check = %q, want yara_realtime_scan_error", finding.Check)
		}
		if finding.Check == "yara_scan_incomplete" {
			t.Fatal("realtime failure still shares the deep scan's coverage-report name")
		}
		if finding.Severity != alert.High {
			t.Errorf("severity = %v, want High", finding.Severity)
		}
	default:
		t.Fatal("a realtime scan error was reported as nothing at all")
	}
}

// Shutdown tears the YARA backend down at daemon.go:1223 while the fanotify
// goroutine is still draining, because d.wg.Wait comes afterwards. Every
// clean restart therefore produced a High "could not inspect a changed file"
// alert. That trains an operator to ignore the exact signal that matters
// when the scanner is genuinely broken. The teardown cannot move after
// wg.Wait, which is unbounded and would hang on a wedged worker, so the
// report is what learns about shutdown.
func TestRealtimeYARAScanErrorIsSilentWhileStopping(t *testing.T) {
	alerts := make(chan alert.Finding, 1)
	stop := make(chan struct{})
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts, stopCh: stop}
	close(stop)

	fm.reportYARAScanError("/home/alice/public_html/x.php", errors.New("supervisor not running"))

	select {
	case finding := <-alerts:
		t.Fatalf("a scan error during shutdown was reported as an outage: %+v", finding)
	default:
	}
}

// The rate limiter must not be spent by a suppressed shutdown report, or the
// first genuine failure after a restart would be swallowed for a minute.
func TestStoppingReportDoesNotSpendTheRateLimit(t *testing.T) {
	alerts := make(chan alert.Finding, 1)
	stop := make(chan struct{})
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts, stopCh: stop}
	close(stop)
	fm.reportYARAScanError("/home/alice/public_html/x.php", errors.New("supervisor not running"))

	live := make(chan alert.Finding, 1)
	fm2 := &FileMonitor{cfg: &config.Config{}, alertCh: live, lastYARAError: fm.lastYARAError}
	fm2.reportYARAScanError("/home/alice/public_html/y.php", errors.New("worker unavailable"))
	select {
	case <-live:
	default:
		t.Fatal("a suppressed shutdown report consumed the rate-limit window")
	}
}

var _ = yara.Active
