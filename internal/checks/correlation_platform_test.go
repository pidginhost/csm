package checks

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

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

func TestLatestStateCorrelationProbesBeforeLock(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	panel := platform.PanelNone
	if !platform.SetOverrides(platform.Overrides{Panel: &panel}) {
		t.Fatal("could not install panel fixture")
	}
	oldRoots := accountHomeRoots
	accountHomeRoots = func() []string { return platform.Detect().AccountHomeRoots() }
	t.Cleanup(func() { accountHomeRoots = oldRoots })

	// Hold the real cold detector in its first host command. File markers
	// avoid blocking FIFO opens and let cleanup release even a failed test.
	dir := t.TempDir()
	t.Setenv("CSM_TEST_CORRELATION_PROBE_DIR", dir)
	t.Setenv("PATH", dir)
	probe := `#!/bin/sh
if [ "$3" = nginx ]; then
    : > "$CSM_TEST_CORRELATION_PROBE_DIR/started"
    while [ ! -f "$CSM_TEST_CORRELATION_PROBE_DIR/release" ]; do
        /bin/sleep 0.01
    done
fi
exit 1
`
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(probe), 0o700); err != nil {
		t.Fatal(err)
	}

	st := newTestStore(t)
	previous := []alert.Finding{{Severity: alert.Critical, Check: "db_rogue_admin", Message: "previous snapshot", FilePath: "/home/previous/site.php"}}
	st.SetLatestFindings(previous)
	batch := []alert.Finding{
		{Severity: alert.Critical, Check: "db_rogue_admin", FilePath: "/home/alice/site.php", Message: "alice"},
		{Severity: alert.Critical, Check: "db_rogue_admin", FilePath: "/home/bob/site.php", Message: "bob"},
		{Severity: alert.Critical, Check: "db_rogue_admin", FilePath: "/home/carol/site.php", Message: "carol"},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		StoreLatestScanFindings(st, purgeNamesFor("db_content"), batch)
	}()
	release := func() {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "release"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("merge did not finish after releasing the platform probe")
		}
	}
	t.Cleanup(release)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(filepath.Join(dir, "started")); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-done:
			t.Fatal("merge finished without running the cold platform probe")
		case <-ctx.Done():
			t.Fatal("platform probe did not start")
		case <-ticker.C:
		}
	}

	read := make(chan []alert.Finding, 1)
	go func() { read <- st.LatestFindings() }()
	select {
	case got := <-read:
		if !reflect.DeepEqual(got, previous) {
			t.Fatalf("probe changed the current snapshot: got %+v, want %+v", got, previous)
		}
	case <-ctx.Done():
		t.Fatal("platform probe blocked readers of the current snapshot")
	}
	release()
	got := st.LatestFindings()
	if counts := checksIn(got); !reflect.DeepEqual(counts, map[string]int{"db_rogue_admin": 3, "coordinated_attack": 1}) {
		t.Fatalf("merge after probe: %+v", got)
	}
	for _, f := range got {
		if f.Check == "coordinated_attack" && (f.Details != "Affected accounts: alice, bob, carol" || f.Timestamp.IsZero()) {
			t.Fatalf("derived finding after probe: %+v", f)
		}
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
