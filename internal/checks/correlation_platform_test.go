package checks

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// Cold platform detection runs host commands. Callers initialize it before
// correlation so the correlator, which may run under the store lock, only
// reads cached account roots.
func TestScanCorrelationUsesInitializedPlatform(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	withAccountHomeRoots(t, "/home")
	rootReads := 0
	accountHomeRoots = func() []string {
		rootReads++
		// With no prior override, acceptance means Detect has not run yet.
		if platform.SetOverrides(platform.Overrides{}) {
			t.Error("correlation reached account roots before platform initialization")
		}
		return []string{"/home"}
	}
	batch := []alert.Finding{
		{Severity: alert.Critical, Check: "db_rogue_admin", FilePath: "/home/alice/site.php"},
		{Severity: alert.Critical, Check: "db_rogue_admin", FilePath: "/home/bob/site.php"},
		{Severity: alert.Critical, Check: "db_rogue_admin", FilePath: "/home/carol/site.php"},
	}
	rows, _ := runParallel(&config.Config{}, nil, []namedCheck{{name: "db_content", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		return batch
	}}}, "test", true)
	if rootReads != 3 || len(rows) != 4 || rows[3].Check != "coordinated_attack" || rows[3].Timestamp.IsZero() {
		t.Fatalf("scan correlation: root reads=%d, findings=%+v", rootReads, rows)
	}
}

func TestCorrelationNoOpCallersSkipPlatformDiscovery(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	StoreLatestScanFindings(nil, []string{"db_rogue_admin"}, nil)
	st := newTestStore(t)
	StoreLatestScanFindings(st, nil, nil)
	rows, purge := runParallel(&config.Config{}, nil, nil, "test", true)
	if len(rows) != 0 || len(purge) != 0 || len(st.LatestFindings()) != 0 {
		t.Fatalf("no-op callers changed findings: rows=%+v purge=%v latest=%+v", rows, purge, st.LatestFindings())
	}
	if !platform.SetOverrides(platform.Overrides{}) {
		t.Fatal("no-op callers initialized platform discovery")
	}
}
