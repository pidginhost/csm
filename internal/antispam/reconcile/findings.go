// Package reconcile runs CSM's antispam integration from the daemon: it
// decides on each pass whether to install, remove or keep the integration,
// asks the root worker to do it, and turns preconditions, worker results
// and rspamd health into findings (spec sections 6.5 and 7).
package reconcile

import (
	"fmt"
	"strconv"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
)

// Finding checks (spec section 7).
const (
	CheckPrecondition    = "antispam_precondition"
	CheckApplyFailed     = "antispam_apply_failed"
	CheckRspamdDown      = "antispam_rspamd_down"
	CheckRspamdRecovered = "antispam_rspamd_recovered"
	CheckScanError       = "antispam_scan_error"
)

// clean escapes control and non-ASCII characters: problem details and
// worker errors can name paths a tenant controls.
func clean(s string) string {
	q := strconv.QuoteToASCII(s)
	return q[1 : len(q)-1]
}

// problemFinding reports one failed precondition and what CSM does about it.
func problemFinding(p antispam.Problem, now time.Time) alert.Finding {
	details := clean(p.Detail)
	switch p.Severity {
	case antispam.Temporary:
		details += ". CSM keeps any installed antispam integration and checks again on its next pass."
	case antispam.Definite:
		details += ". CSM does not install its antispam integration, and removes an installed one when it can do so safely."
	}
	return alert.Finding{
		Severity:  alert.Warning,
		Check:     CheckPrecondition,
		Message:   "Antispam precondition not met: " + p.Code,
		Details:   details,
		Timestamp: now,
	}
}

// resultFinding reports a worker run that did not complete. A busy lock
// is retried, not reported. Worker errors stay in the daemon log: they
// can carry the worker's diagnostics.
func resultFinding(op string, r antispam.Result, err error, now time.Time) (alert.Finding, bool) {
	f := alert.Finding{Severity: alert.Warning, Check: CheckApplyFailed, Timestamp: now}
	switch {
	case err != nil:
		f.Message = "Antispam " + op + " returned no result"
		f.Details = "CSM could not confirm the outcome of the antispam " + op + "; the daemon log has the worker's error. CSM runs it again on its next pass."
		return f, true
	case r.OK || r.Busy:
		return alert.Finding{}, false
	}
	f.Message = fmt.Sprintf("Antispam %s failed at %s", op, r.FailedStep)
	f.Details = clean(r.Error)
	switch r.Rollback {
	case antispam.RollbackVerified:
		f.Details += ". CSM restored the previous state and tries again on its next pass."
	case antispam.RollbackFailed:
		f.Severity = alert.Critical
		f.Details += ". CSM could not confirm that the previous state was restored; check Exim and rspamd now. CSM repairs the integration on its next pass."
	default:
		f.Details += ". CSM changed nothing."
	}
	return f, true
}

// The health findings. Down and scan errors keep one identity each while
// they last; recovery is a one-time notice.
func rspamdDownFinding(socket string, since time.Time) alert.Finding {
	return alert.Finding{
		Severity: alert.Warning, Check: CheckRspamdDown, DedupKey: "rspamd", Timestamp: since,
		Message: "rspamd does not answer on the antispam scan socket",
		Details: fmt.Sprintf("%d /ping probes in a row over %s failed. Exim delivers mail without spam filtering until rspamd answers again.", pingDown, clean(socket)),
	}
}

func rspamdRecoveredFinding(socket string, now time.Time) alert.Finding {
	return alert.Finding{
		Severity: alert.Warning, Check: CheckRspamdRecovered, Timestamp: now,
		Message: "rspamd answers on the antispam scan socket again",
		Details: fmt.Sprintf("%d /ping probes in a row over %s succeeded.", pingUp, clean(socket)),
	}
}

func scanErrorFinding(count int, first, last time.Time) alert.Finding {
	scans := "scans"
	if count == 1 {
		scans = "scan"
	}
	return alert.Finding{
		Severity: alert.Warning, Check: CheckScanError, DedupKey: "scan", Timestamp: last,
		Message: "Antispam scans are failing",
		Details: fmt.Sprintf("Exim logged %d failed %s since %s, the last at %s. Mail is delivered without spam filtering while scans fail; check rspamd's log.",
			count, scans, first.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339)),
	}
}
