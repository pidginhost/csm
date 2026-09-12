package checks

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

func TestWPCorePersistentFailureIsVisibleAndRecovers(t *testing.T) {
	setupPluginStore(t)
	roots, _ := wpCoreQueueFixtures(t, 1)
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	refused := refusedCommand(t)
	recovered := false
	withMockCmd(t, &mockCmd{runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
		wpCoreQueuePath(t, name, args)
		if recovered {
			return []byte("Success: WordPress installation verifies against checksums.\n"), nil
		}
		return []byte("Error: Failed to get core checksums: checksum service unavailable.\n"), refused
	}})
	for cycle := 1; cycle <= 2; cycle++ {
		findings := CheckWPCore(withWPInstallCache(context.Background()), &config.Config{}, st)
		if cycle == 1 && len(findings) != 0 {
			t.Fatalf("first failure should wait for another cycle: %+v", findings)
		}
		if cycle == 2 {
			if len(findings) != 1 {
				t.Fatalf("persistent verification failure is invisible: got %d findings, want 1", len(findings))
			}
			f := findings[0]
			if f.Check != "wp_core_unverified" || f.Severity != alert.Warning || f.FilePath != filepath.Dir(roots[0]) || !strings.Contains(f.Details, "checksum") {
				t.Fatalf("failure lacks its installation and reason: %+v", f)
			}
		}
		StoreLatestScanFindings(st, []string{"wp_core_unverified"}, findings)
	}
	if q := WPCoreQueueStatus(time.Now()); q.DroppedTotal != 0 {
		t.Fatalf("completed refusals became lost work: %+v", q)
	}
	recovered = true
	findings := CheckWPCore(withWPInstallCache(context.Background()), &config.Config{}, st)
	StoreLatestScanFindings(st, []string{"wp_core_unverified"}, findings)
	if len(st.LatestFindings()) != 0 {
		t.Fatalf("successful verification did not clear the finding: %+v", st.LatestFindings())
	}
}

func TestPluginVerificationCountsOnlyFreshAttempts(t *testing.T) {
	db := setupPluginStore(t)
	pluginQueueRoots(t, 1)
	refused := refusedCommand(t)
	attempts := 0
	withMockCmd(t, &mockCmd{runContextStdout: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if !strings.Contains(strings.Join(args, " "), "plugin list") {
			return []byte("https://example.test"), nil
		}
		attempts++
		return []byte("PHP Fatal error: configuration failed"), refused
	}})
	ctx := withWPInstallCache(context.Background())
	CheckOutdatedPlugins(ctx, &config.Config{}, nil)
	CheckVulnerablePlugins(ctx, &config.Config{}, nil)
	if got := CheckWPPluginVerification(ctx, &config.Config{}, nil); len(got) != 0 {
		t.Fatalf("shared consumers counted as separate cycles: %+v", got)
	}
	if attempts != 1 {
		t.Fatalf("shared inventory ran %d times in one cycle, want 1", attempts)
	}
	if err := db.SetPluginRefreshTime(time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := CheckWPPluginVerification(withWPInstallCache(context.Background()), &config.Config{}, nil); len(got) != 0 || attempts != 1 {
		t.Fatalf("cache hit became an attempt: findings=%+v attempts=%d", got, attempts)
	}
}

func TestWPVerificationReasonsAndNonInstallations(t *testing.T) {
	refused := refusedCommand(t)
	for _, tc := range []struct {
		name          string
		out           []byte
		err           error
		state, reason string
	}{
		{"not_wordpress", []byte("Error: This does not seem to be a WordPress installation."), refused, "not_wordpress", "did not find"},
		{"fatal", []byte("PHP Fatal error: configuration failed"), refused, "unverified", "initialization"},
		{"network", []byte("Error: Failed to get core checksums"), refused, "unverified", "checksum"},
		{"missing", nil, exec.ErrNotFound, "unverified", "executable"},
		{"timeout_with_partial", []byte("Warning: File doesn't verify against checksum: wp-includes/version.php"), context.DeadlineExceeded, "unverified", "timed out"},
		{"malformed_inventory", nil, errWPInventoryParse, "unverified", "JSON"},
		{"no_output", nil, errors.Join(errWPInventoryNoOutput, refused), "unverified", "no plugin inventory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := wpVerificationFailure(tc.err, tc.out)
			if got.State != tc.state || !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("classification: %+v", got)
			}
		})
	}
}

func TestWPCoreVerificationRetainsFailuresOnCancellationAndClearsRemovedSites(t *testing.T) {
	db := setupPluginStore(t)
	roots, fs := wpCoreQueueFixtures(t, 1)
	refused := refusedCommand(t)
	withMockCmd(t, &mockCmd{runContext: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("PHP Fatal error: configuration failed"), refused
	}})
	for range 2 {
		CheckWPCore(withWPInstallCache(context.Background()), nil, nil)
	}
	ctx, cancel := context.WithCancel(withWPInstallCache(context.Background()))
	cancel()
	CheckWPCore(ctx, nil, nil)
	rows, err := db.WPVerification("core")
	if err != nil || rows[filepath.Dir(roots[0])].Failures != 2 {
		t.Fatalf("cancellation erased persistent failure: %+v %v", rows, err)
	}
	fs.glob = func(string) ([]string, error) { return nil, errors.New("fixture incomplete discovery") }
	CheckWPCore(withWPInstallCache(context.Background()), nil, nil)
	rows, err = db.WPVerification("core")
	if err != nil || rows[filepath.Dir(roots[0])].Failures != 2 {
		t.Fatalf("standalone partial discovery erased persistent failure: %+v %v", rows, err)
	}
	fs.glob = func(string) ([]string, error) { return nil, nil }
	if got := CheckWPCore(withWPInstallCache(context.Background()), nil, nil); len(got) != 0 {
		t.Fatalf("removed installation stayed unverified: %+v", got)
	}
	rows, err = db.WPVerification("core")
	if err != nil || len(rows) != 0 {
		t.Fatalf("removed installation remains in coverage counts: %+v %v", rows, err)
	}
}

func TestWPVerificationFailureDoesNotBecomeAnIncident(t *testing.T) {
	for _, check := range []string{"wp_core_unverified", "wp_plugin_inventory_unverified"} {
		f := alert.Finding{Check: check, Severity: alert.Warning, TenantID: "alice", FilePath: "/home/alice/site", SourceIP: "192.0.2.10"}
		if key := incident.KeyFor(f); !key.IsEmpty() {
			t.Fatalf("coverage failure entered containment: %+v", key)
		}
	}
}

func TestWPVerificationRenderingEscapesAccountControlledPaths(t *testing.T) {
	db := setupPluginStore(t)
	path := "/home/alice/site\nFORGED\x1b[31m"
	paths := map[string]string{path: "alice"}
	for i := range 2 {
		if err := db.UpdateWPVerification("core", time.Now().Add(time.Duration(i)*time.Hour), "", paths, map[string]store.WPVerificationResult{path: {State: "unverified", Reason: "wp-cli timed out"}}, true); err != nil {
			t.Fatal(err)
		}
	}
	findings := wpVerificationFindings(context.Background(), db, "core", "wp_core", nil)
	if len(findings) != 1 || strings.Contains(findings[0].Message, "\n") || strings.Contains(findings[0].Details, "\nFORGED") || strings.ContainsAny(findings[0].Details, "\x1b") {
		t.Fatalf("unescaped diagnostic: %+v", findings)
	}
}

func TestWPVerificationRepeatedFailureDoesNotFloodAlerts(t *testing.T) {
	db := setupPluginStore(t)
	at := time.Now()
	paths := map[string]string{"/home/alice/site": "alice"}
	results := map[string]store.WPVerificationResult{"/home/alice/site": {State: "unverified", Reason: "wp-cli timed out"}}
	var previous alert.Finding
	for i := range 3 {
		if err := db.UpdateWPVerification("core", at.Add(time.Duration(i)*time.Hour), "", paths, results, true); err != nil {
			t.Fatal(err)
		}
		findings := wpVerificationFindings(context.Background(), db, "core", "wp_core", nil)
		if i == 0 {
			continue
		}
		if len(findings) != 1 {
			t.Fatalf("missing persistent finding: %+v", findings)
		}
		if i == 2 && (previous.Key() != findings[0].Key() || previous.Fingerprint() != findings[0].Fingerprint()) {
			t.Fatal("a new last-attempt time creates another alert for the same outage")
		}
		previous = findings[0]
	}
}

func TestWPCorePartialIntegrityOutputDoesNotHideVerificationFailure(t *testing.T) {
	db := setupPluginStore(t)
	roots, _ := wpCoreQueueFixtures(t, 1)
	refused := refusedCommand(t)
	withMockCmd(t, &mockCmd{runContext: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("Warning: File doesn't verify against checksum: wp-includes/version.php\nError: Failed to get core checksums: service unavailable\n"), refused
	}})
	for range 2 {
		CheckWPCore(withWPInstallCache(context.Background()), nil, nil)
	}
	rows, err := db.WPVerification("core")
	if err != nil || rows[filepath.Dir(roots[0])].State != "unverified" {
		t.Fatalf("partial findings concealed incomplete verification: %+v %v", rows, err)
	}
}

func TestPluginPersistentInventoryFailureIsVisible(t *testing.T) {
	setupPluginStore(t)
	pluginQueueRoots(t, 1)
	refused := refusedCommand(t)
	withMockCmd(t, &mockCmd{runContextStdout: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if !strings.Contains(strings.Join(args, " "), "plugin list") {
			return []byte("https://example.test"), nil
		}
		return []byte("PHP Fatal error: configuration failed\n"), refused
	}})
	for cycle := 1; cycle <= 2; cycle++ {
		findings := CheckWPPluginVerification(withWPInstallCache(context.Background()), &config.Config{}, nil)
		if cycle == 1 && len(findings) != 0 {
			t.Fatalf("first inventory failure should wait: %+v", findings)
		}
		if cycle == 2 && (len(findings) != 1 || findings[0].Check != "wp_plugin_inventory_unverified" || findings[0].FilePath != "/home/alice/public_html/site0") {
			t.Fatalf("persistent inventory failure is invisible: %+v", findings)
		}
	}
}

func TestWPCoreRecoveryClearsOnlyRecoveredCoverageDuringPartialDiscovery(t *testing.T) {
	setupPluginStore(t)
	roots, fs := wpCoreQueueFixtures(t, 2)
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	refused := refusedCommand(t)
	recoverFirst := false
	withMockCmd(t, &mockCmd{runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
		path := wpCoreQueuePath(t, name, args)
		if recoverFirst && path == filepath.Dir(roots[0]) {
			return []byte("Success: WordPress installation verifies against checksums."), nil
		}
		return []byte("Error: Failed to get core checksums."), refused
	}})
	scan := func() {
		t.Helper()
		findings, purge := runParallelWithContext(context.Background(), &config.Config{}, st, []namedCheck{{"wp_core", CheckWPCore}}, string(TierDeep), true)
		StoreLatestScanFindings(st, purge, findings)
	}
	scan()
	scan()
	if len(st.LatestFindings()) != 2 {
		t.Fatalf("persistent failures missing: %+v", st.LatestFindings())
	}
	recoverFirst = true
	originalGlob := fs.glob
	fs.glob = func(pattern string) ([]string, error) {
		matches, _ := originalGlob(pattern)
		return matches, errors.New("fixture incomplete discovery")
	}
	scan()
	got := st.LatestFindings()
	if len(got) != 1 || got[0].FilePath != filepath.Dir(roots[1]) {
		t.Fatalf("partial discovery prevented per-install recovery: %+v", got)
	}
}

func TestPluginVerificationHonorsDisabledInventoryConsumers(t *testing.T) {
	setupPluginStore(t)
	pluginQueueRoots(t, 1)
	withMockCmd(t, &mockCmd{runContextStdout: func(context.Context, string, ...string) ([]byte, error) {
		t.Error("disabled inventory consumers started wp-cli")
		return nil, exec.ErrNotFound
	}})
	cfg := &config.Config{DisabledChecks: []string{" outdated_plugins ", " vulnerable_plugins "}}
	if got := CheckWPPluginVerification(withWPInstallCache(context.Background()), cfg, nil); len(got) != 0 {
		t.Fatalf("disabled inventory consumers emitted findings: %+v", got)
	}
}
