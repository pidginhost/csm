package checks

import (
	"context"
	"sync/atomic"
	"testing"

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

	findings := runParallel(cfg, nil, checks, "test")

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

	_ = runParallel(cfg, nil, checks, "test")
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

	_ = runParallel(cfg, nil, checks, "test")

	if ranA {
		t.Error("whitespace-padded check_a should still be treated as disabled")
	}
	if !ranB {
		t.Error("check_b should have run")
	}
}
