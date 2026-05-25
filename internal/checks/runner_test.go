package checks

import (
	"context"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// --- criticalChecks / deepChecks list non-empty -----------------------

func TestCriticalChecksNotEmpty(t *testing.T) {
	list := criticalChecks()
	if len(list) == 0 {
		t.Error("criticalChecks should return non-empty list")
	}
	for _, nc := range list {
		if nc.name == "" {
			t.Error("check name should not be empty")
		}
		if nc.fn == nil {
			t.Errorf("check %q has nil function", nc.name)
		}
	}
}

func TestDeepChecksNotEmpty(t *testing.T) {
	list := deepChecks()
	if len(list) == 0 {
		t.Error("deepChecks should return non-empty list")
	}
	for _, nc := range list {
		if nc.name == "" {
			t.Error("check name should not be empty")
		}
		if nc.fn == nil {
			t.Errorf("check %q has nil function", nc.name)
		}
	}
}

func TestRunnerFindingNamesMatchesRegisteredRunnersAndChecks(t *testing.T) {
	runners := map[string]struct{}{}
	for _, nc := range criticalChecks() {
		runners[nc.name] = struct{}{}
	}
	for _, nc := range deepChecks() {
		runners[nc.name] = struct{}{}
	}
	for _, nc := range reducedDeepChecks() {
		runners[nc.name] = struct{}{}
	}

	for runner, findings := range runnerFindingNames {
		if _, ok := runners[runner]; !ok {
			t.Errorf("runnerFindingNames contains unknown runner %q", runner)
		}
		if len(findings) == 0 {
			t.Errorf("runnerFindingNames[%q] has no finding names", runner)
		}
		for _, finding := range findings {
			if _, ok := LookupCheck(finding); !ok {
				t.Errorf("runnerFindingNames[%q] contains unregistered finding %q", runner, finding)
			}
		}
	}

	for runner := range runners {
		if _, ok := runnerFindingNames[runner]; !ok {
			t.Errorf("scheduled runner %q is missing from runnerFindingNames", runner)
		}
	}
}

// --- PerfCheckNamesForTier -------------------------------------------

func TestPerfCheckNamesForTierCritical(t *testing.T) {
	names := PerfCheckNamesForTier(TierCritical)
	for _, n := range names {
		if n[:5] != "perf_" {
			t.Errorf("non-perf check in critical tier: %q", n)
		}
	}
}

func TestPerfCheckNamesForTierAll(t *testing.T) {
	names := PerfCheckNamesForTier(TierAll)
	if len(names) == 0 {
		t.Error("TierAll should return perf checks")
	}
}

func TestPerfCheckNamesForTierDeep(t *testing.T) {
	names := PerfCheckNamesForTier(TierDeep)
	// Deep tier has perf checks
	for _, n := range names {
		if n[:5] != "perf_" {
			t.Errorf("non-perf check: %q", n)
		}
	}
}

func TestLatestPurgeCheckNamesForTierCriticalIncludesEmittedNames(t *testing.T) {
	names := LatestPurgeCheckNamesForTier(TierCritical)
	for _, want := range []string{"wp_bruteforce", "wp_login_bruteforce", "wp_user_enumeration", "xmlrpc_abuse"} {
		if !slices.Contains(names, want) {
			t.Fatalf("critical purge names missing %q in %v", want, names)
		}
	}
	if slices.Contains(names, "check_timeout") {
		t.Fatalf("critical purge names included generic check_timeout")
	}
	if slices.Contains(names, "outdated_plugins") {
		t.Fatalf("critical purge names included deep check outdated_plugins")
	}
}

func TestLatestPurgeCheckNamesForReducedDeepSkipsFanotifyReplacedChecks(t *testing.T) {
	names := LatestPurgeCheckNamesForReducedDeep()
	if !slices.Contains(names, "outdated_plugins") {
		t.Fatalf("reduced deep purge names missing outdated_plugins")
	}
	if slices.Contains(names, "webshell") {
		t.Fatalf("reduced deep purge names included fanotify-replaced webshell")
	}
}

func TestStoreLatestScanFindingsFiltersActionsAndRefreshesCorrelation(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	st.SetLatestFindings([]alert.Finding{
		{Check: "auto_block", Message: "old block"},
		{Check: "auto_response", Message: "old action"},
		{Check: "cross_account_malware", Message: "old correlation"},
	})

	StoreLatestScanFindings(st, []string{"webshell"}, []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found in /home/alice/public_html/a.php"},
		{Severity: alert.Critical, Check: "webshell", Message: "Found in /home/bob/public_html/b.php"},
		{Severity: alert.Critical, Check: "auto_block", Message: "new block"},
		{Severity: alert.Critical, Check: "auto_response", Message: "new action"},
	})

	got := st.LatestFindings()
	for _, f := range got {
		if f.Check == "auto_block" || f.Check == "auto_response" {
			t.Fatalf("volatile action stored in latest findings: %+v", f)
		}
	}
	if !containsFindingCheck(got, "webshell") {
		t.Fatalf("webshell finding missing from latest findings: %+v", got)
	}
	if !containsFindingCheck(got, "cross_account_malware") {
		t.Fatalf("derived correlation missing from latest findings: %+v", got)
	}

	StoreLatestScanFindings(st, []string{"webshell"}, nil)
	got = st.LatestFindings()
	if containsFindingCheck(got, "webshell") {
		t.Fatalf("stale webshell finding remained: %+v", got)
	}
	if containsFindingCheck(got, "cross_account_malware") {
		t.Fatalf("stale derived correlation remained: %+v", got)
	}
}

func containsFindingCheck(findings []alert.Finding, check string) bool {
	for _, f := range findings {
		if f.Check == check {
			return true
		}
	}
	return false
}

// --- DisabledChecks honored at runner level --------------------------

func TestRunParallelSkipsDisabledChecks(t *testing.T) {
	ranA, ranB, ranC := false, false, false
	checks := []namedCheck{
		{"check_a", func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			ranA = true
			return []alert.Finding{{Check: "check_a", Severity: alert.Warning, Message: "a"}}
		}},
		{"check_b", func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			ranB = true
			return []alert.Finding{{Check: "check_b", Severity: alert.Warning, Message: "b"}}
		}},
		{"check_c", func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			ranC = true
			return []alert.Finding{{Check: "check_c", Severity: alert.Warning, Message: "c"}}
		}},
	}

	cfg := &config.Config{}
	cfg.DisabledChecks = []string{"check_a", "check_c"}

	findings, _ := runParallel(cfg, nil, checks, "test", false)

	if ranA {
		t.Error("check_a should have been skipped (in DisabledChecks)")
	}
	if !ranB {
		t.Error("check_b should have run (not in DisabledChecks)")
	}
	if ranC {
		t.Error("check_c should have been skipped (in DisabledChecks)")
	}

	for _, f := range findings {
		if f.Check == "check_a" || f.Check == "check_c" {
			t.Errorf("disabled check %q produced a finding: %+v", f.Check, f)
		}
	}
}

func TestRunParallelSkipsDisabledFindingNameAliases(t *testing.T) {
	tests := []struct {
		name     string
		disabled string
		runner   string
	}{
		{name: "waf rules finding disables WAF runner", disabled: "waf_rules", runner: "waf_status"},
		{name: "crontab finding disables crontab runner", disabled: "suspicious_crontab", runner: "crontabs"},
		{name: "runner ID compatibility still works", disabled: "crontabs", runner: "crontabs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ranDisabled, ranOther atomic.Int32
			checks := []namedCheck{
				{tt.runner, func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
					ranDisabled.Add(1)
					return []alert.Finding{{Check: tt.disabled, Severity: alert.Warning, Message: "disabled"}}
				}},
				{"other_runner", func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
					ranOther.Add(1)
					return []alert.Finding{{Check: "other_check", Severity: alert.Warning, Message: "other"}}
				}},
			}

			cfg := &config.Config{DisabledChecks: []string{tt.disabled}}

			findings, _ := runParallel(cfg, nil, checks, "test", false)

			if got := ranDisabled.Load(); got != 0 {
				t.Fatalf("%s ran %d time(s), want skipped", tt.runner, got)
			}
			if got := ranOther.Load(); got != 1 {
				t.Fatalf("other_runner ran %d time(s), want 1", got)
			}
			for _, f := range findings {
				if f.Check == tt.disabled {
					t.Fatalf("disabled finding %q was returned: %+v", tt.disabled, f)
				}
			}
		})
	}
}

func TestRunParallelDisabledFindingAliasPurgesStoredFindings(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	st.SetLatestFindings([]alert.Finding{
		{Check: "waf_rules", Severity: alert.Warning, Message: "old waf finding"},
		{Check: "other_check", Severity: alert.Warning, Message: "keep"},
	})

	var ranDisabled atomic.Int32
	checks := []namedCheck{
		{"waf_status", func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			ranDisabled.Add(1)
			return []alert.Finding{{Check: "waf_rules", Severity: alert.Warning, Message: "disabled"}}
		}},
		{"other_runner", func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			return nil
		}},
	}

	cfg := &config.Config{DisabledChecks: []string{"waf_rules"}}
	findings, purge := runParallel(cfg, st, checks, "test", false)
	if got := ranDisabled.Load(); got != 0 {
		t.Fatalf("disabled runner executed %d time(s), want 0", got)
	}
	if containsFindingCheck(findings, "waf_rules") {
		t.Fatalf("disabled runner emitted finding: %+v", findings)
	}
	if !slices.Contains(purge, "waf_rules") {
		t.Fatalf("purge list missing disabled finding alias waf_rules: %v", purge)
	}

	StoreLatestScanFindings(st, purge, findings)
	got := st.LatestFindings()
	if containsFindingCheck(got, "waf_rules") {
		t.Fatalf("disabled stale waf_rules finding remained: %+v", got)
	}
	if !containsFindingCheck(got, "other_check") {
		t.Fatalf("unowned finding was purged unexpectedly: %+v", got)
	}
}

func TestRunParallelDisabledChecksEmptyRunsAll(t *testing.T) {
	var ran atomic.Int32
	mkCheck := func(name string) namedCheck {
		return namedCheck{name, func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			ran.Add(1)
			return nil
		}}
	}
	checks := []namedCheck{mkCheck("a"), mkCheck("b")}

	cfg := &config.Config{} // DisabledChecks unset

	_, _ = runParallel(cfg, nil, checks, "test", false)
	if got := ran.Load(); got != 2 {
		t.Errorf("with empty DisabledChecks all checks should run, got ran=%d want 2", got)
	}
}

func TestRunParallelDisabledChecksTrimsAndIgnoresBlanks(t *testing.T) {
	ranA, ranB := false, false
	checks := []namedCheck{
		{"check_a", func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			ranA = true
			return nil
		}},
		{"check_b", func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			ranB = true
			return nil
		}},
	}

	cfg := &config.Config{}
	cfg.DisabledChecks = []string{"  check_a  ", "", "   "}

	_, _ = runParallel(cfg, nil, checks, "test", false)

	if ranA {
		t.Error("whitespace-padded check_a should still be treated as disabled")
	}
	if !ranB {
		t.Error("check_b should have run")
	}
}

// A throttled check that gets skipped in cycle N must NOT appear in the
// per-scan purge list, otherwise StoreLatestScanFindings wipes the
// findings emitted during cycle N-1 (when the throttle window had not
// elapsed). Regression guard: previously perf_* findings disappeared
// every other deep scan when interval and throttle were both 60 minutes.
func TestRunParallelThrottledCheckSkippedAndExcludedFromPurge(t *testing.T) {
	prev := checkThrottleMin["test_throttled"]
	checkThrottleMin["test_throttled"] = 60
	defer func() {
		if prev == 0 {
			delete(checkThrottleMin, "test_throttled")
		} else {
			checkThrottleMin["test_throttled"] = prev
		}
	}()

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = store.Close() }()

	var ran atomic.Int32
	checks := []namedCheck{
		{"test_throttled", func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			ran.Add(1)
			return []alert.Finding{{Check: "test_throttled", Severity: alert.Warning, Message: "fired"}}
		}},
		{"test_unthrottled", func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			return nil
		}},
	}

	cfg := &config.Config{}

	// First cycle: throttle entry absent, check runs and is in purge list.
	findings1, purge1 := runParallel(cfg, store, checks, "test", false)
	if ran.Load() != 1 {
		t.Fatalf("first cycle: throttled check should have run once, got %d", ran.Load())
	}
	if !slices.Contains(purge1, "test_throttled") {
		t.Fatalf("first cycle: purge list missing test_throttled: %v", purge1)
	}
	if !containsFindingCheck(findings1, "test_throttled") {
		t.Fatalf("first cycle: findings missing test_throttled: %+v", findings1)
	}

	// Second cycle within the throttle window: check skipped, purge list
	// must exclude it so the prior finding stays in the latest set.
	findings2, purge2 := runParallel(cfg, store, checks, "test", false)
	if ran.Load() != 1 {
		t.Fatalf("second cycle: throttled check should NOT have re-run, ran=%d", ran.Load())
	}
	if slices.Contains(purge2, "test_throttled") {
		t.Fatalf("second cycle: purge list must not include throttled-out test_throttled: %v", purge2)
	}
	if containsFindingCheck(findings2, "test_throttled") {
		t.Fatalf("second cycle: throttled-out check must not emit findings: %+v", findings2)
	}
}

// --- Per-check timeout budgets ---------------------------------------

// TestTimeoutForHeavyChecksGetExpandedBudget pins the heavy-filesystem
// checks (webshells, php_content, filesystem, htaccess, file_index,
// phishing) to a longer execution budget than the default 5 minutes.
// On busy shared hosts these legitimately exceed 5 minutes on hundreds
// of WP installs, generating noisy check_timeout warnings even when the
// scan would have completed cleanly given another minute or two.
func TestTimeoutForHeavyChecksGetExpandedBudget(t *testing.T) {
	for _, name := range []string{"webshells", "php_content", "filesystem", "htaccess", "file_index", "phishing"} {
		got := timeoutFor(name)
		if got != heavyCheckTimeout {
			t.Errorf("timeoutFor(%q) = %s, want %s", name, got, heavyCheckTimeout)
		}
	}
}

func TestTimeoutForDefaultChecksKeepStandardBudget(t *testing.T) {
	for _, name := range []string{"crontabs", "ssh_logins", "mail_queue", "wp_bruteforce", "unknown_runner"} {
		got := timeoutFor(name)
		if got != checkTimeout {
			t.Errorf("timeoutFor(%q) = %s, want %s", name, got, checkTimeout)
		}
	}
}

func TestCheckDurationBucketsCoverHeavyTimeout(t *testing.T) {
	want := heavyCheckTimeout.Seconds()
	got := checkDurationBuckets[len(checkDurationBuckets)-1]
	if got != want {
		t.Fatalf("last check-duration bucket = %.0fs, want %.0fs", got, want)
	}
}

// TestRunParallelTimeoutMessageReflectsCheckBudget guards against the
// previous bug where the timeout finding's message hard-coded the
// global 5-minute string, hiding the fact that heavy checks now get a
// different ceiling.
func TestRunParallelTimeoutMessageReflectsCheckBudget(t *testing.T) {
	// Use a sub-second timeout via a check that blocks past its budget.
	// timeoutFor is hit from runParallel, so we plant a heavy-name entry
	// that we know returns heavyCheckTimeout, and a normal-name entry
	// that returns checkTimeout. The check functions block on ctx.Done
	// to force the timeout path deterministically; we then assert the
	// emitted message names the right budget.
	heavyName := "webshells"
	normalName := "ssh_logins"
	checks := []namedCheck{
		{heavyName, func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			<-ctx.Done()
			return nil
		}},
		{normalName, func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			<-ctx.Done()
			return nil
		}},
	}

	// Shrink the live budgets just for this test by swapping the
	// vars/consts indirectly: the runner reads timeoutFor(), which
	// reads heavyChecks + the two constants. We avoid mutating consts
	// and instead time-bound the test by overriding the func pointer.
	prevHeavy := timeoutForFunc
	t.Cleanup(func() { timeoutForFunc = prevHeavy })
	timeoutForFunc = func(name string) time.Duration {
		if name == heavyName {
			return 30 * time.Millisecond
		}
		return 10 * time.Millisecond
	}

	cfg := &config.Config{}
	findings, _ := runParallel(cfg, nil, checks, "test", false)

	var saw [2]string
	for _, f := range findings {
		if f.Check != "check_timeout" {
			continue
		}
		switch {
		case strings.Contains(f.Message, "'"+heavyName+"'"):
			saw[0] = f.Message
		case strings.Contains(f.Message, "'"+normalName+"'"):
			saw[1] = f.Message
		}
	}
	if saw[0] == "" {
		t.Fatalf("expected check_timeout finding for %s, got %+v", heavyName, findings)
	}
	if !strings.Contains(saw[0], "30ms") {
		t.Errorf("heavy check timeout message must name 30ms budget, got %q", saw[0])
	}
	if saw[1] == "" {
		t.Fatalf("expected check_timeout finding for %s, got %+v", normalName, findings)
	}
	if !strings.Contains(saw[1], "10ms") {
		t.Errorf("normal check timeout message must name 10ms budget, got %q", saw[1])
	}
}
