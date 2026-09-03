package checks

import (
	"context"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func hasCoverageGap(gaps map[string]map[string]bool, check, path string) bool {
	return gaps[check][path]
}

func TestWithCoverageGapsAcceptsNilContext(t *testing.T) {
	//nolint:staticcheck // Deliberately exercise the defensive nil-context API path.
	ctx, gaps := WithCoverageGaps(nil)
	if ctx == nil || gaps == nil || len(gaps.Paths()) != 0 {
		t.Fatalf("WithCoverageGaps(nil) = (%v, %+v), want usable empty collector", ctx, gaps)
	}
}

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

func TestRunnerScopesCoverageGapToLogicalOwner(t *testing.T) {
	const path = "/home/shared/public_html/index.php"
	tests := []struct {
		owner   string
		finding string
	}{
		{owner: "yara_deep", finding: "yara_match_scheduled"},
		{owner: logicalOwnerJSTaintDeep, finding: "js_keylogger_dataflow"},
		{owner: logicalOwnerPHPTaintDeep, finding: "php_remote_taint"},
	}

	for _, tc := range tests {
		t.Run(tc.owner, func(t *testing.T) {
			check := namedCheck{name: "yara_deep", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
				markCheckIncompletePath(ctx, tc.owner, path)
				return nil
			}}
			scanCtx, gaps := WithCoverageGaps(context.Background())
			_, _ = runParallelWithContext(scanCtx, &config.Config{}, nil, []namedCheck{check}, "deep", true)

			got := gaps.Paths()
			for _, other := range tests {
				if hasCoverageGap(got, other.finding, path) != (other.finding == tc.finding) {
					t.Errorf("gap owner %s produced finding gaps %+v", tc.owner, got)
				}
			}
		})
	}
}

func TestRunnerReusedCoverageContextReplacesPriorCycle(t *testing.T) {
	const oldPath = "/home/a/public_html/old-gap.php"
	scanCtx, gaps := WithCoverageGaps(context.Background())
	withGap := namedCheck{name: "yara_deep", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		markCheckIncompletePath(ctx, "yara_deep", oldPath)
		return nil
	}}
	_, _ = runParallelWithContext(scanCtx, &config.Config{}, nil, []namedCheck{withGap}, "deep", true)
	if !hasCoverageGap(gaps.Paths(), "yara_match_scheduled", oldPath) {
		t.Fatal("first scan did not publish its path gap")
	}

	complete := namedCheck{name: "yara_deep", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		return nil
	}}
	_, _ = runParallelWithContext(scanCtx, &config.Config{}, nil, []namedCheck{complete}, "deep", true)
	if got := gaps.Paths(); len(got) != 0 {
		t.Fatalf("later complete scan retained a prior cycle's gaps: %+v", got)
	}
}

func TestRunnerNestedScanDoesNotMergeCollectors(t *testing.T) {
	const innerPath = "/home/a/public_html/inner-gap.php"
	const outerPath = "/home/a/public_html/outer-gap.php"
	scanCtx, gaps := WithCoverageGaps(context.Background())

	outer := namedCheck{name: "yara_deep", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		inner := namedCheck{name: "yara_deep", fn: func(innerCtx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			markCheckIncompletePath(innerCtx, "yara_deep", innerPath)
			return nil
		}}
		_, _ = runParallelWithContext(ctx, &config.Config{}, nil, []namedCheck{inner}, "deep", true)
		markCheckIncompletePath(ctx, "yara_deep", outerPath)
		return nil
	}}
	_, _ = runParallelWithContext(scanCtx, &config.Config{}, nil, []namedCheck{outer}, "deep", true)

	got := gaps.Paths()
	if !hasCoverageGap(got, "yara_match_scheduled", outerPath) {
		t.Fatalf("outer scan gap was not published: %+v", got)
	}
	if hasCoverageGap(got, "yara_match_scheduled", innerPath) {
		t.Fatalf("nested scan gap leaked into its caller's cycle: %+v", got)
	}
}

func TestRunnerLateTimedOutWriterCannotChangePublishedGaps(t *testing.T) {
	previousTimeout := timeoutForFunc
	t.Cleanup(func() { timeoutForFunc = previousTimeout })
	timeoutForFunc = func(string) time.Duration { return 20 * time.Millisecond }

	const latePath = "/home/a/public_html/late-gap.php"
	release := make(chan struct{})
	wrote := make(chan struct{})
	check := namedCheck{name: "yara_deep", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		<-release
		markCheckIncompletePath(ctx, "yara_deep", latePath)
		close(wrote)
		return nil
	}}
	scanCtx, gaps := WithCoverageGaps(context.Background())
	_, _ = runParallelWithContext(scanCtx, &config.Config{}, nil, []namedCheck{check}, "deep", true)
	close(release)
	select {
	case <-wrote:
	case <-time.After(time.Second):
		t.Fatal("timed-out check goroutine did not finish")
	}

	if got := gaps.Paths(); len(got) != 0 {
		t.Fatalf("timed-out check changed the completed scan snapshot: %+v", got)
	}
}
