package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// newRollingAccounts builds one docroot per account under a temp /home tree,
// each holding a single dormant payload outside the fixed suspicious dirs, so
// only rolling coverage can reach it. Returns the temp root and the logical
// /home path of each account's payload, in account order.
func newRollingAccounts(t *testing.T, accounts ...string) (string, map[string]string) {
	t.Helper()
	root := t.TempDir()
	payloads := make(map[string]string, len(accounts))
	for _, account := range accounts {
		dir := filepath.Join(root, "home", account, "public_html", "assets")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "dormant.php"), rollingDormantPHP)
		payloads[account] = "/home/" + account + "/public_html/assets/dormant.php"
	}
	return root, payloads
}

// Rolling coverage sized its window with the per-account file cap and then ran
// it once per account, so a host with hundreds of accounts asked for hundreds
// of windows in one check budget and never finished. The cap is the budget for
// the cycle, shared by the accounts the cycle reaches.
func TestRollingContentSharesOneBudgetAcrossAccounts(t *testing.T) {
	resetPHPContentScanCounts(t)
	root, payloads := newRollingAccounts(t, "aaa", "zzz")
	withMockOS(t, rollingRootOS{root: root})
	useRollingStore(t)

	findings := CheckPHPContent(context.Background(), rollingCfg(1), nil)

	if !findsPath(findings, payloads["aaa"]) {
		t.Fatalf("first account in rolling order was not scanned: %+v", findings)
	}
	if findsPath(findings, payloads["zzz"]) {
		t.Fatalf("second account was scanned although the cycle budget was spent: %+v", findings)
	}
}

// The account walk always restarts at the alphabetically first account, so once
// the budget ran out mid-host the same prefix was rescanned every cycle and the
// tail was never covered. Accounts are ordered by how long ago they last
// completed a traversal, so the cycle after one wraps moves on to the next.
func TestRollingContentAdvancesToNextAccountNextCycle(t *testing.T) {
	resetPHPContentScanCounts(t)
	root, payloads := newRollingAccounts(t, "aaa", "zzz")
	withMockOS(t, rollingRootOS{root: root})
	useRollingStore(t)

	cfg := rollingCfg(1)
	ctx := context.Background()

	first := CheckPHPContent(ctx, cfg, nil)
	if !findsPath(first, payloads["aaa"]) {
		t.Fatalf("cycle 1 did not scan the first account: %+v", first)
	}

	second := CheckPHPContent(ctx, cfg, nil)
	if !findsPath(second, payloads["zzz"]) {
		t.Fatalf("cycle 2 did not advance to the uncovered account: %+v", second)
	}
}

// Rolling coverage stamps clean files outside the fixed suspicious dirs, and
// those stamps are carried forward across cycles now. Enumeration reads every
// directory under the account's docroots, so a file that has since been
// deleted must be dropped rather than kept forever.
func TestRollingContentPrunesDeletedFileFromEnumeratedDir(t *testing.T) {
	resetPHPContentScanCounts(t)
	root, _ := newRollingAccounts(t, "aaa")
	withMockOS(t, rollingRootOS{root: root})
	useRollingStore(t)

	gone := "/home/aaa/public_html/assets/removed.php"
	stateDir := t.TempDir()
	cfg := rollingCfg(10)
	cfg.StatePath = stateDir
	savePHPContentCache(stateDir, phpContentCache{gone: {Mtime: 1, Size: 1}})

	CheckPHPContent(context.Background(), cfg, nil)

	if _, ok := loadPHPContentCache(stateDir)[gone]; ok {
		t.Fatal("stamp for a deleted file in an enumerated directory survived")
	}
}

// Rolling covers one window per cycle, so most of an account's stamps come
// from earlier cycles. They have to survive the cycles that do not revisit
// them, or every window pays the full read cost again.
func TestRollingContentKeepsStampsFromEarlierWindows(t *testing.T) {
	resetPHPContentScanCounts(t)
	root := t.TempDir()
	dir := filepath.Join(root, "home", "aaa", "public_html", "assets")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "a.php"), rollingBenignPHP)
	writeFile(t, filepath.Join(dir, "b.php"), rollingBenignPHP)
	withMockOS(t, rollingRootOS{root: root})
	useRollingStore(t)

	stateDir := t.TempDir()
	cfg := rollingCfg(1)
	cfg.StatePath = stateDir

	CheckPHPContent(context.Background(), cfg, nil)
	CheckPHPContent(context.Background(), cfg, nil)

	cache := loadPHPContentCache(stateDir)
	for _, name := range []string{"a.php", "b.php"} {
		if _, ok := cache["/home/aaa/public_html/assets/"+name]; !ok {
			t.Fatalf("stamp for %s is missing after two windows: %v", name, cache)
		}
	}
}
