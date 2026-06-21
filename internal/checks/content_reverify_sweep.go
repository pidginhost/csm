package checks

import "github.com/pidginhost/csm/internal/alert"

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

// ReverifyStaleContentFindings re-checks every content-reverifiable finding in
// the store against current detection logic and dismisses those that are now
// confirmed stale (file gone, or identical bytes the current classifier no
// longer flags). It reuses reverifyContentFinding, so the same safety invariant
// holds: a still-present file is cleared only when its bytes are unchanged since
// detection. Returns the dismissed findings for the caller to log. Read-only
// except for dismissing confirmed-stale findings.
func ReverifyStaleContentFindings(store LatestFindingStore) []ContentReverifyDismissal {
	var dismissed []ContentReverifyDismissal
	for _, f := range store.LatestFindings() {
		if !IsContentReverifiable(f.Check) {
			continue
		}
		res := reverifyContentFinding(VerifyInput{
			Check: f.Check, Message: f.Message, Details: f.Details, Path: f.FilePath,
			ContentSHA256: f.ContentSHA256, DetectLogic: f.DetectLogic,
		})
		if res.Checked && res.Resolved {
			key := f.Key()
			store.DismissFinding(key)
			store.DismissLatestFinding(key)
			dismissed = append(dismissed, ContentReverifyDismissal{Check: f.Check, Path: f.FilePath, Detail: res.Detail})
		}
	}
	return dismissed
}
