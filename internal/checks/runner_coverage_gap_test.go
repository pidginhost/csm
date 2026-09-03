package checks

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// A coverage gap that names a file freezes only that file's finding. Before
// this, one permanently unreadable file -- a 20.8 MB error_log over the scan
// limit -- marked the whole YARA owner incomplete on every cycle, so no
// yara_match_scheduled finding on the host could ever be retired.

func TestRunnerPerFileGapRetiresOtherFindings(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	const gapped = "/home/b/public_html/error_log"
	const covered = "/home/a/public_html/old.php"
	st.SetLatestFindings([]alert.Finding{
		{Check: "yara_match_scheduled", Severity: alert.Critical, Message: "gapped", FilePath: gapped},
		{Check: "yara_match_scheduled", Severity: alert.Critical, Message: "covered", FilePath: covered},
	})

	check := namedCheck{name: "yara_deep", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		markCheckIncompletePath(ctx, "yara_deep", gapped)
		return []alert.Finding{{Check: "yara_scan_incomplete", Severity: alert.High, Message: "1 entry"}}
	}}

	scanCtx, gaps := WithCoverageGaps(context.Background())
	findings, purge := runParallelWithContext(scanCtx, &config.Config{}, st, []namedCheck{check}, "deep", true)
	StoreLatestScanFindingsWithGaps(st, purge, findings, gaps.Paths())

	got := st.LatestFindings()
	var keptCovered, keptGapped bool
	for _, f := range got {
		switch f.FilePath {
		case covered:
			keptCovered = true
		case gapped:
			keptGapped = true
		}
	}
	if keptCovered {
		t.Errorf("a file the scan covered kept a finding it did not raise again: %+v", got)
	}
	if !keptGapped {
		t.Errorf("the unreadable file lost its finding even though the scan never read it: %+v", got)
	}
}

// A gap the scan cannot pin to a file -- an unreadable directory, a failed
// Lstat that may hide a whole subtree -- still freezes the owner. The scan has
// said nothing about an unknown range, so nothing may be retired.
func TestRunnerUnattributableGapStillFreezesTheOwner(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	st.SetLatestFindings([]alert.Finding{
		{Check: "yara_match_scheduled", Severity: alert.Critical, Message: "prior window", FilePath: "/home/a/x.php"},
	})

	check := namedCheck{name: "yara_deep", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		markCheckIncompletePath(ctx, "yara_deep", "/home/b/error_log")
		markCheckIncomplete(ctx, "yara_deep") // a directory-level gap
		return []alert.Finding{{Check: "yara_scan_incomplete", Severity: alert.High, Message: "partial"}}
	}}

	scanCtx, gaps := WithCoverageGaps(context.Background())
	findings, purge := runParallelWithContext(scanCtx, &config.Config{}, st, []namedCheck{check}, "deep", true)
	StoreLatestScanFindingsWithGaps(st, purge, findings, gaps.Paths())

	if !containsFindingCheck(st.LatestFindings(), "yara_match_scheduled") {
		t.Error("an unknowable gap range must keep the owner's findings")
	}
}

// A fully covered scan retires what it did not raise, unchanged.
func TestRunnerCompleteScanStillRetiresFindings(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	st.SetLatestFindings([]alert.Finding{
		{Check: "yara_match_scheduled", Severity: alert.Critical, Message: "stale", FilePath: "/home/a/x.php"},
	})

	check := namedCheck{name: "yara_deep", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		return nil
	}}

	scanCtx, gaps := WithCoverageGaps(context.Background())
	findings, purge := runParallelWithContext(scanCtx, &config.Config{}, st, []namedCheck{check}, "deep", true)
	StoreLatestScanFindingsWithGaps(st, purge, findings, gaps.Paths())

	if containsFindingCheck(st.LatestFindings(), "yara_match_scheduled") {
		t.Error("a complete scan must retire a finding it did not raise again")
	}
}
