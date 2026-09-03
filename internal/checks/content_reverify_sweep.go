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
func ReverifyStaleFindingsContext(ctx context.Context, store LatestFindingStore) ([]ContentReverifyDismissal, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return nil, false
	}
	var dismissed []ContentReverifyDismissal
	var exposureVhosts *exposureVhostIndex
	for _, f := range store.LatestFindings() {
		if ctx.Err() != nil {
			return dismissed, false
		}
		if !autoReverifiable(f.Check) {
			continue
		}
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
			return dismissed, false
		}
		switch {
		case res.Checked && res.Resolved:
			if store.DismissFindingIfLatest(f) {
				dismissed = append(dismissed, ContentReverifyDismissal{Check: f.Check, Path: f.FilePath, Detail: res.Detail})
			}
		case isAutomaticallyDemoted(f) && !res.Demote:
			// A demotion holds only while the replacement keeps satisfying the
			// inert-content gate. Restore on a positive match and on every
			// uncertain or newly-active shape alike; otherwise a second edit
			// into a detection gap would leave live malware at Warning.
			if store.RestoreLatestFindingSeverity(f) {
				dismissed = append(dismissed, ContentReverifyDismissal{
					Check: f.Check, Path: f.FilePath, Detail: res.Detail, Promoted: true})
			}
		case res.Checked && res.Demote && f.Severity > alert.Warning:
			// Remediated but unproven: keep it, stop ranking it beside live
			// threats. Demoting an already-Warning finding would be churn.
			if store.DemoteLatestFinding(f, alert.Warning) {
				dismissed = append(dismissed, ContentReverifyDismissal{
					Check: f.Check, Path: f.FilePath, Detail: res.Detail, Demoted: true})
			}
		}
	}
	return dismissed, true
}
