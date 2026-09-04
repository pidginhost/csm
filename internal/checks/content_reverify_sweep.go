package checks

import (
	"context"

	"github.com/pidginhost/csm/internal/alert"
)

// LatestFindingStore is the subset of the state store the sweep needs.
type LatestFindingStore interface {
	LatestFindings() []alert.Finding
	// Each mutation takes the snapshot verification actually looked at, so a
	// scan or realtime alert that refreshed the same key while the re-check was
	// in flight is never overwritten by the older verdict.
	DismissFindingIfLatest(expected alert.Finding) bool
	DemoteLatestFinding(expected alert.Finding, severity alert.Severity) bool
	RestoreLatestFindingSeverity(expected alert.Finding) bool
}

// ContentReverifyDismissal records one finding the sweep cleared, for the
// caller to audit-log (the checks package has no logger of its own).
type ContentReverifyDismissal struct {
	Check  string
	Path   string
	Detail string
	// Demoted and Promoted distinguish the outcomes for the audit log: a
	// cleared finding is gone, a demoted one is still listed at a lower
	// severity, a promoted one had an earlier demotion reversed.
	Demoted  bool
	Promoted bool
}

// isAutomaticallyDemoted reports whether this finding is sitting at Warning
// because a previous sweep lowered it, rather than because it was raised there.
func isAutomaticallyDemoted(f alert.Finding) bool {
	return f.Severity == alert.Warning &&
		f.DemotedFrom >= alert.High && f.DemotedFrom <= alert.Critical
}

// ShouldRestoreSeverity reports whether an automatic demotion must be reversed.
// A demotion holds only while the replacement keeps satisfying the inert-content
// gate. Restore on a positive match and on every uncertain or newly-active shape
// alike; otherwise a second edit into a detection gap would leave live malware
// at Warning.
func ShouldRestoreSeverity(f alert.Finding, res VerifyResult) bool {
	return isAutomaticallyDemoted(f) && !res.Demote
}

// ShouldDemoteSeverity reports whether a verdict retires a remediated but
// unproven finding from the live queue. It is never a clear: an attacker must
// not retire a finding by editing the file. Demoting an already-Warning finding
// would be churn.
//
// The unattended sweep and the operator's Re-check both ask this, so the two
// cannot disagree about what a verdict means.
func ShouldDemoteSeverity(f alert.Finding, res VerifyResult) bool {
	return res.Checked && res.Demote && f.Severity > alert.Warning
}

// autoReverifiable reports whether the sweep may re-check and dismiss a finding
// of this type on its own. Membership is deliberately narrow: only families
// whose verifier re-runs the same test that raised the finding and fails closed
// on any uncertainty. Every other registered verifier stays operator-driven
// through the web UI.
func autoReverifiable(check string) bool {
	return IsContentReverifiable(check) || isExposedVerifiable(check)
}

// ReverifyStaleFindings re-checks every auto-reverifiable finding in the store
// against current detection logic and dismisses those that are now confirmed
// stale: for content findings a file that is gone, or identical bytes the
// current classifier no longer flags; for web_exposed_* findings an exposure
// that a complete pinned probe no longer confirms. Dispatch goes through the
// verifier registry, so each family keeps its own safety invariant -- a
// still-present file is cleared only when its bytes are unchanged since
// detection, and an exposure only when a complete probe says the server no
// longer serves it. Returns the dismissed findings for the caller to log.
// Read-only except for dismissing confirmed-stale findings.
func ReverifyStaleFindings(store LatestFindingStore) []ContentReverifyDismissal {
	dismissed, _ := ReverifyStaleFindingsContext(context.Background(), store)
	return dismissed
}

// ReverifyStaleFindingsContext is the cancellable form used by the daemon so a
// large exposure queue cannot delay shutdown for every remaining probe. The
// bool is false after cancellation so the daemon leaves the sweep version
// uncommitted and retries it on the next start.
// ReverifySweepStats describes what a sweep actually did. A sweep that changed
// nothing is otherwise silent, which makes "ran and found nothing"
// indistinguishable from "never ran" and from "could not check a single
// finding" -- the difference an operator needs when findings are not draining.
type ReverifySweepStats struct {
	Considered int
	Cleared    int
	Demoted    int
	Promoted   int
	Unchecked  int
	// TopUncheckedReason is the most common reason a finding could not be
	// re-checked at all, which is where a silent sweep usually goes wrong.
	TopUncheckedReason string
}

func ReverifyStaleFindingsContext(ctx context.Context, store LatestFindingStore) ([]ContentReverifyDismissal, bool) {
	out, _, complete := ReverifyStaleFindingsStats(ctx, store)
	return out, complete
}

// ReverifyStaleFindingsStats is ReverifyStaleFindingsContext with a summary of
// everything the sweep looked at, including the findings it could not check.
func ReverifyStaleFindingsStats(ctx context.Context, store LatestFindingStore) ([]ContentReverifyDismissal, ReverifySweepStats, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	var dismissed []ContentReverifyDismissal
	var stats ReverifySweepStats
	if ctx.Err() != nil {
		return nil, stats, false
	}
	uncheckedReasons := map[string]int{}
	var exposureVhosts *exposureVhostIndex
	for _, f := range store.LatestFindings() {
		if ctx.Err() != nil {
			return dismissed, stats, false
		}
		if !autoReverifiable(f.Check) {
			continue
		}
		stats.Considered++
		in := VerifyInput{
			Check: f.Check, Message: f.Message, Details: f.Details, Path: f.FilePath,
			ContentSHA256: f.ContentSHA256, DetectLogic: f.DetectLogic,
			Context: ctx,
		}
		if isExposedVerifiable(f.Check) {
			if exposureVhosts == nil {
				loaded := loadExposureVhostIndex()
				exposureVhosts = &loaded
			}
			in.exposureVhosts = exposureVhosts
		}
		res := VerifyFindingInput(in)
		if ctx.Err() != nil {
			return dismissed, stats, false
		}
		switch {
		case res.Checked && res.Resolved:
			if store.DismissFindingIfLatest(f) {
				stats.Cleared++
				dismissed = append(dismissed, ContentReverifyDismissal{Check: f.Check, Path: f.FilePath, Detail: res.Detail})
			}
		case ShouldRestoreSeverity(f, res):
			if store.RestoreLatestFindingSeverity(f) {
				stats.Promoted++
				dismissed = append(dismissed, ContentReverifyDismissal{
					Check: f.Check, Path: f.FilePath, Detail: res.Detail, Promoted: true})
			}
		case ShouldDemoteSeverity(f, res):
			if store.DemoteLatestFinding(f, alert.Warning) {
				stats.Demoted++
				dismissed = append(dismissed, ContentReverifyDismissal{
					Check: f.Check, Path: f.FilePath, Detail: res.Detail, Demoted: true})
			}
		case !res.Checked:
			// The verifier could not form an opinion at all -- a scanner that
			// was unavailable, a file that changed under it. This is the
			// bucket that looks identical to a sweep that never ran.
			stats.Unchecked++
			uncheckedReasons[res.Detail]++
		}
	}
	top, topN := "", 0
	for reason, n := range uncheckedReasons {
		if n > topN || (n == topN && reason < top) {
			top, topN = reason, n
		}
	}
	stats.TopUncheckedReason = top
	return dismissed, stats, true
}
