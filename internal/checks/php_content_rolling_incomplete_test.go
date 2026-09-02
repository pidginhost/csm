package checks

import (
	"context"
	"testing"
)

// A rolling window covers a slice of the account's PHP files per cycle.
// Findings from earlier windows are not re-emitted in this cycle, so the
// runner must not treat the check as complete and purge them: a partial
// window marks php_content incomplete, exactly as yara_deep does.
func TestRollingContentPartialWindowMarksCheckIncomplete(t *testing.T) {
	resetPHPContentScanCounts(t)
	fx := newRollingFixture(t)
	withMockOS(t, rollingRootOS{root: fx.root})
	useRollingStore(t)
	cfg := rollingCfg(2)

	// Six files, cap two: this window cannot cover the account.
	ctx, _ := withIncompleteCheckCollector(context.Background())
	CheckPHPContent(ctx, cfg, nil)
	if !checkMarkedIncomplete(ctx, "php_content") {
		t.Fatal("partial rolling window left php_content marked complete; earlier windows' findings would be purged")
	}
}

func TestRollingContentFullCoverageLeavesCheckComplete(t *testing.T) {
	resetPHPContentScanCounts(t)
	fx := newRollingFixture(t)
	withMockOS(t, rollingRootOS{root: fx.root})
	useRollingStore(t)
	// A cap above the file count covers everything in one window.
	cfg := rollingCfg(100)

	ctx, _ := withIncompleteCheckCollector(context.Background())
	CheckPHPContent(ctx, cfg, nil)
	if checkMarkedIncomplete(ctx, "php_content") {
		t.Fatal("a window that covered every file marked php_content incomplete")
	}
}

func TestRollingContentWrapStillMarksCheckIncomplete(t *testing.T) {
	resetPHPContentScanCounts(t)
	fx := newRollingFixture(t)
	withMockOS(t, rollingRootOS{root: fx.root})
	useRollingStore(t)
	cfg := rollingCfg(2)

	// Seven files at a cap of two cross the end of the list on the fourth
	// window. That completes a traversal across runs, not full coverage in the
	// fourth run, so earlier windows' findings still need carrying forward.
	for range 3 {
		CheckPHPContent(context.Background(), cfg, nil)
	}
	ctx, _ := withIncompleteCheckCollector(context.Background())
	CheckPHPContent(ctx, cfg, nil)
	if !checkMarkedIncomplete(ctx, "php_content") {
		t.Fatal("a wrapping partial window marked php_content complete and would purge earlier findings")
	}
}
