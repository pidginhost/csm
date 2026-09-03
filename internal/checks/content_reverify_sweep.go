package checks

import (
	"context"

	"github.com/pidginhost/csm/internal/alert"
)

// LatestFindingStore is the subset of the state store the sweep needs.
type LatestFindingStore interface {
	LatestFindings() []alert.Finding
	DismissFinding(key string)
	DismissLatestFinding(key string)
}

// ContentReverifyDismissal records one finding the sweep cleared, for the
// caller to audit-log (the checks package has no logger of its own).
type ContentReverifyDismissal struct {
	Check  string
	Path   string
	Detail string
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
		if res.Checked && res.Resolved {
			key := f.Key()
			store.DismissFinding(key)
			store.DismissLatestFinding(key)
			dismissed = append(dismissed, ContentReverifyDismissal{Check: f.Check, Path: f.FilePath, Detail: res.Detail})
		}
	}
	return dismissed, true
}
