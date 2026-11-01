// Package reconcile runs CSM's antispam integration from the daemon: it
// decides on each pass whether to install, remove or keep the integration,
// asks the root worker to do it, and turns preconditions, worker results
// and rspamd health into findings (spec sections 6.5 and 7).
package reconcile

import (
	"fmt"
	"strconv"
	"strings"
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
	CheckFeed            = "antispam_feed"
	CheckIPMap           = "antispam_ip_map"
	CheckControllerOpen  = "antispam_controller_open"
	CheckLearning        = "antispam_learning"
	CheckFileReplaced    = "antispam_file_replaced"
)

// clean escapes control and non-ASCII characters: problem details and
// worker errors can name paths a tenant controls.
func clean(s string) string {
	q := strconv.QuoteToASCII(s)
	return q[1 : len(q)-1]
}

// feedFinding reports a feed or map redirect CSM left out, or loaded
// blocklist rules that differ from CSM's. Feed problems never block core.
func feedFinding(p antispam.Problem, now time.Time) alert.Finding {
	return alert.Finding{
		Severity:  alert.Warning,
		Check:     CheckFeed,
		DedupKey:  p.Key,
		Message:   "Antispam feed problem: " + clean(p.Key),
		Details:   clean(p.Detail) + ". Core spam filtering is unaffected.",
		Timestamp: now,
	}
}

// controllerFinding reports one rspamd controller listener that tenant
// processes can use for admin or read-only requests (learning spec 9).
func controllerFinding(p antispam.Problem, now time.Time) alert.Finding {
	return alert.Finding{
		Severity: alert.Warning,
		Check:    CheckControllerOpen,
		DedupKey: clean(p.Key),
		Message:  "rspamd controller may be reachable by other users: " + clean(p.Key),
		Details: clean(p.Detail) + ". Local processes, including customer scripts, may use this listener to read " +
			"rspamd's history or change its settings. For TCP, set secure_ip = []; in override.d/worker-controller.inc " +
			"while a controller password is set. For Unix sockets, use mode 0600 and root or rspamd ownership " +
			"for the socket and parent directories. Keep those directories unwritable by other users and remove extended ACLs.",
		Timestamp: now,
	}
}

// IPMapFinding reports that rspamd is not using CSM's current IP map, or
// that the map could not be written (feeds spec 8.4, 8.5).
func IPMapFinding(detail string, now time.Time) alert.Finding {
	return alert.Finding{
		Severity:  alert.Warning,
		Check:     CheckIPMap,
		DedupKey:  "ip_map",
		Message:   "Antispam IP map problem",
		Details:   clean(detail) + ". Core spam filtering is unaffected.",
		Timestamp: now,
	}
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

func scanErrorFinding(count int, first, last time.Time, stack antispam.MailStack, milterAction string) alert.Finding {
	scans := "scans"
	if count == 1 {
		scans = "scan"
	}
	details := fmt.Sprintf("Exim logged %d failed %s since %s, the last at %s. Mail is delivered without spam filtering while scans fail; check rspamd's log.",
		count, scans, first.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339))
	if stack == antispam.StackPostfix {
		details = fmt.Sprintf("Postfix logged %d failed %s since %s, the last at %s. %s; check rspamd's log.",
			count, scans, first.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339), milterEffect(milterAction))
	}
	return alert.Finding{
		Severity: alert.Warning, Check: CheckScanError, DedupKey: "scan", Timestamp: last,
		Message: "Antispam scans are failing",
		Details: details,
	}
}

// milterEffect says what postfix does with mail while rspamd's milter
// fails, by milter_default_action, which postfix reads without regard to
// case.
func milterEffect(action string) string {
	switch strings.ToLower(action) {
	case "accept":
		return "Mail is delivered without spam filtering while scans fail"
	case "tempfail":
		return "Mail is deferred until rspamd answers"
	case "reject":
		return "Mail is rejected while scans fail"
	case "quarantine":
		return "Mail is held in postfix's hold queue while scans fail"
	}
	return "Postfix's milter_default_action is unknown, so what happens to that mail is unknown"
}

// replacedFinding reports one operator file CSM backed up and replaced,
// until the operator deletes the backup. restores is set for a Postfix
// host's actions.conf, which a return to dry run puts back.
func replacedFinding(rep antispam.Replacement, restores bool, now time.Time) alert.Finding {
	advice := ". Move any settings you still need into a file CSM does not manage, then delete the backup to clear this warning."
	if restores {
		advice = ". Returning antispam to dry run puts it back and clears this warning; delete the backup if you do not want it back."
	}
	return alert.Finding{
		Severity:  alert.Warning,
		Check:     CheckFileReplaced,
		DedupKey:  rep.Backup,
		Message:   "Antispam replaced " + clean(rep.Path),
		Details:   "CSM replaced " + clean(rep.Path) + " and kept your previous file at " + clean(rep.Backup) + advice,
		Timestamp: now,
	}
}

// learningFinding reports one learning condition, one finding per reason.
func learningFinding(p antispam.Problem, now time.Time) alert.Finding {
	return alert.Finding{
		Severity:  alert.Warning,
		Check:     CheckLearning,
		Message:   "Antispam learning: " + p.Key,
		Details:   clean(p.Detail),
		DedupKey:  "learning:" + clean(p.Key),
		Timestamp: now,
	}
}
