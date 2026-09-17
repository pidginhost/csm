package checks

import (
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// The sweep and the operator's Re-check must reach the same verdict about a
// finding's severity. They used to disagree by omission: the sweep demoted a
// remediated finding, while the Re-check button computed the same verdict and
// applied nothing. Both now ask these two predicates, so a future change cannot
// move one without the other.

func TestShouldDemoteSeverity(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    alert.Finding
		res  VerifyResult
		want bool
	}{
		{
			name: "checked demotable critical",
			f:    alert.Finding{Severity: alert.Critical},
			res:  VerifyResult{Checked: true, Demote: true},
			want: true,
		},
		{
			name: "checked demotable high",
			f:    alert.Finding{Severity: alert.High},
			res:  VerifyResult{Checked: true, Demote: true},
			want: true,
		},
		{
			name: "already warning is not demoted again",
			f:    alert.Finding{Severity: alert.Warning},
			res:  VerifyResult{Checked: true, Demote: true},
			want: false,
		},
		{
			name: "unchecked verdict never demotes",
			f:    alert.Finding{Severity: alert.Critical},
			res:  VerifyResult{Checked: false, Demote: true},
			want: false,
		},
		{
			name: "checked but not demotable",
			f:    alert.Finding{Severity: alert.Critical},
			res:  VerifyResult{Checked: true, Demote: false},
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldDemoteSeverity(tc.f, tc.res); got != tc.want {
				t.Fatalf("ShouldDemoteSeverity = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestShouldRestoreSeverity(t *testing.T) {
	demoted := alert.Finding{Severity: alert.Warning, DemotedFrom: alert.Critical}
	for _, tc := range []struct {
		name string
		f    alert.Finding
		res  VerifyResult
		want bool
	}{
		{
			name: "demoted finding that stopped being inert",
			f:    demoted,
			res:  VerifyResult{Checked: true, Demote: false},
			want: true,
		},
		{
			name: "an inconclusive re-check still restores",
			// Fail safe: a replacement CSM can no longer read or classify must
			// go back to its original severity, or a second edit into a
			// detection gap parks live malware at Warning for good.
			f:    demoted,
			res:  VerifyResult{Checked: false},
			want: true,
		},
		{
			name: "still inert stays demoted",
			f:    demoted,
			res:  VerifyResult{Checked: true, Demote: true},
			want: false,
		},
		{
			name: "a finding raised at warning is not an automatic demotion",
			f:    alert.Finding{Severity: alert.Warning},
			res:  VerifyResult{Checked: true, Demote: false},
			want: false,
		},
		{
			name: "a live critical is not a restore candidate",
			f:    alert.Finding{Severity: alert.Critical},
			res:  VerifyResult{Checked: true, Demote: false},
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldRestoreSeverity(tc.f, tc.res); got != tc.want {
				t.Fatalf("ShouldRestoreSeverity = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSweepResolvesAutomaticallyDemotedFindingBeforeRestore(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	f := alert.Finding{
		Check: "suspicious_php_content", Message: "removed file", FilePath: filepath.Join(tmp, "gone.php"),
		Severity: alert.Warning, DemotedFrom: alert.Critical,
	}
	store := &fakeFindingStore{
		findings: []alert.Finding{f}, dismissed: map[string]bool{}, promoted: map[string]bool{},
	}

	outcomes := ReverifyStaleFindings(store)
	if len(outcomes) != 1 || outcomes[0].Promoted || outcomes[0].Demoted {
		t.Fatalf("resolved automatic demotion must be cleared first, got %+v", outcomes)
	}
	if !store.dismissed[f.Key()] || store.promoted[f.Key()] {
		t.Fatalf("resolved finding used the wrong mutation: dismissed=%v promoted=%v", store.dismissed, store.promoted)
	}
}
