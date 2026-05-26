package checks

import (
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// accountScanTruncatedSink is the optional callback the daemon wires
// up at startup so rankPathsByMtimeDesc can surface "I dropped N
// files past the cap" as an operator-visible Finding. nil means the
// truncation only shows up in stderr/journal logs.
var accountScanTruncatedSink func(alert.Finding)

// SetAccountScanTruncatedSink registers the emitter. The daemon's
// alert dispatcher is the production target. Tests pass a recorder.
func SetAccountScanTruncatedSink(fn func(alert.Finding)) {
	accountScanTruncatedSink = fn
}

// emitAccountScanTruncated fires the per-tick warning when the
// account scanner clipped its input. Operators discovering the same
// detection signal repeatedly missing should raise
// thresholds.account_scan_max_files; without this Finding the only
// trace is a stderr log line many operators do not collect.
func emitAccountScanTruncated(dropped, cap int) {
	if accountScanTruncatedSink == nil {
		return
	}
	accountScanTruncatedSink(alert.Finding{
		Severity:  alert.Warning,
		Check:     "account_scan_truncated",
		Message:   fmt.Sprintf("Account scan truncated: %d file(s) skipped past cap of %d", dropped, cap),
		Details:   "Raise thresholds.account_scan_max_files if recent detection coverage matters more than scan duration.",
		Timestamp: time.Now(),
	})
}
