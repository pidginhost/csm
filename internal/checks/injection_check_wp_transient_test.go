package checks

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// CheckWPTransientBloat behaviour:
//   - perfEnabled=false → nil
//   - throttled (recent run) → nil
//   - no web roots → empty findings
//   (success path with DB lookup is covered by e2e tests on real MySQL.)

func TestCheckWPTransientBloatPerfDisabledReturnsNil(t *testing.T) {
	disabled := false
	cfg := &config.Config{}
	cfg.Performance.Enabled = &disabled
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	if got := CheckWPTransientBloat(context.Background(), cfg, st); got != nil {
		t.Errorf("perf-disabled should return nil, got %d findings", len(got))
	}
}

func TestCheckWPTransientBloatThrottledReturnsNil(t *testing.T) {
	enabled := true
	cfg := &config.Config{}
	cfg.Performance.Enabled = &enabled
	cfg.Performance.WPTransientWarnMB = 1
	cfg.Performance.WPTransientCriticalMB = 10
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	// First run marks the throttle timestamp.
	_ = CheckWPTransientBloat(context.Background(), cfg, st)
	// Second immediate run must short-circuit.
	if got := CheckWPTransientBloat(context.Background(), cfg, st); got != nil {
		t.Errorf("throttled call should return nil, got %d findings", len(got))
	}
}

func TestCheckWPTransientBloatNoAccountRootsEmpty(t *testing.T) {
	enabled := true
	cfg := &config.Config{}
	cfg.Performance.Enabled = &enabled
	cfg.Performance.WPTransientWarnMB = 1
	cfg.Performance.WPTransientCriticalMB = 10
	// No AccountRoots, no cPanel detection → ResolveWebRoots yields nil,
	// loop body never runs, findings stay empty.
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	got := CheckWPTransientBloat(context.Background(), cfg, st)
	if len(got) != 0 {
		t.Errorf("no web roots should yield empty findings, got %d: %+v", len(got), got)
	}
}
