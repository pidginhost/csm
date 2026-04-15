package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// CheckWPCron behaviour:
//   - perfEnabled=false → returns nil
//   - throttled (recent run) → returns nil
//   - no web roots → returns no findings
//   - web root with wp-config.php missing DISABLE_WP_CRON → emits warning

func TestCheckWPCronPerfDisabledReturnsNil(t *testing.T) {
	disabled := false
	cfg := &config.Config{}
	cfg.Performance.Enabled = &disabled

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	if got := CheckWPCron(context.Background(), cfg, st); got != nil {
		t.Errorf("perf-disabled should return nil, got %d findings", len(got))
	}
}

func TestCheckWPCronThrottledReturnsNil(t *testing.T) {
	enabled := true
	cfg := &config.Config{}
	cfg.Performance.Enabled = &enabled

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	// Force a recent run so the throttle blocks the second call.
	_ = CheckWPCron(context.Background(), cfg, st)
	got := CheckWPCron(context.Background(), cfg, st)
	if got != nil {
		t.Errorf("throttled call should return nil, got %d findings", len(got))
	}
}

func TestCheckWPCronWithRealWPConfigEmitsWarning(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)

	tmp := t.TempDir()
	docRoot := filepath.Join(tmp, "alice", "public_html")
	if err := os.MkdirAll(docRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docRoot, "wp-config.php"),
		[]byte("<?php\ndefine('DB_NAME', 'wp');\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		AccountRoots: []string{filepath.Join(tmp, "*", "public_html")},
	}
	enabled := true
	cfg.Performance.Enabled = &enabled

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	withMockOS(t, &mockOS{
		glob:     filepath.Glob,
		stat:     os.Stat,
		readDir:  os.ReadDir,
		readFile: os.ReadFile,
		open:     os.Open,
	})

	got := CheckWPCron(context.Background(), cfg, st)
	if len(got) == 0 {
		t.Fatal("expected at least one perf_wp_cron finding")
	}
	found := false
	for _, f := range got {
		if f.Check == "perf_wp_cron" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected perf_wp_cron finding, got %+v", got)
	}
}

// --- perfEnabled -------------------------------------------------------

func TestPerfEnabledNilDefaultsToTrue(t *testing.T) {
	cfg := &config.Config{}
	if !perfEnabled(cfg) {
		t.Error("perfEnabled with nil Enabled should default to true")
	}
}

func TestPerfEnabledHonorsExplicitFalse(t *testing.T) {
	cfg := &config.Config{}
	v := false
	cfg.Performance.Enabled = &v
	if perfEnabled(cfg) {
		t.Error("perfEnabled with explicit false should return false")
	}
}

func TestPerfEnabledHonorsExplicitTrue(t *testing.T) {
	cfg := &config.Config{}
	v := true
	cfg.Performance.Enabled = &v
	if !perfEnabled(cfg) {
		t.Error("perfEnabled with explicit true should return true")
	}
}
