package checks

import (
	"context"
	"errors"
	"fmt"
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

// recordWPVerificationFailures drives two cycles so every install reaches the
// persistent-failure threshold without going through wp-cli.
func recordWPVerificationFailures(t *testing.T, db *store.DB, reasons map[string]string, account string) {
	t.Helper()
	paths := make(map[string]string, len(reasons))
	results := make(map[string]store.WPVerificationResult, len(reasons))
	for path, reason := range reasons {
		paths[path] = account
		results[path] = store.WPVerificationResult{State: "unverified", Reason: reason}
	}
	at := time.Now()
	for cycle := range 2 {
		if err := db.UpdateWPVerification("core", at.Add(time.Duration(cycle)*time.Hour), "", paths, results, true); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWPVerificationAccountScansKeepInstallationIdentity(t *testing.T) {
	for _, kind := range []string{"core", "plugins"} {
		t.Run(kind, func(t *testing.T) {
			db := setupPluginStore(t)
			paths := make(map[string]string)
			results := make(map[string]store.WPVerificationResult)
			for account, count := range map[string]int{"alice": 11, "bob": 2} {
				for i := range count {
					path := fmt.Sprintf("/home/%s/site%02d", account, i)
					paths[path] = account
					results[path] = store.WPVerificationResult{State: "unverified", Reason: "wp-cli timed out"}
				}
			}
			at := time.Now()
			for cycle := range 2 {
				if err := db.UpdateWPVerification(kind, at.Add(time.Duration(cycle)*time.Hour), "", paths, results, true); err != nil {
					t.Fatal(err)
				}
			}
			host := wpVerificationFindings(context.Background(), db, kind, "", nil)
			if len(host) != 1 || host[0].FilePath != "" || host[0].TenantID != "" || !strings.Contains(host[0].Details, "Installations affected: 13\n") {
				t.Fatalf("host-wide cause split at an account boundary: %+v", host)
			}
			if key := incident.KeyFor(host[0]); !key.IsEmpty() {
				t.Fatalf("host coverage warning entered incidents: %+v", key)
			}
			if CanVerify(host[0].Check) || HasFix(host[0].Check) {
				t.Fatal("coverage warning offers file re-check or remediation")
			}
			for account, count := range map[string]int{"alice": 11, "bob": 2} {
				ctx := ContextWithAccountScope(context.Background(), account)
				findings := wpVerificationFindings(ctx, db, kind, "", nil)
				if len(findings) != count {
					t.Fatalf("account %s lost installation detail: got %d findings, want %d", account, len(findings), count)
				}
				for _, f := range findings {
					if paths[f.FilePath] != account || f.TenantID != account || f.DedupKey != f.FilePath {
						t.Fatalf("account scan lost its scoped installation identity: %+v", f)
					}
					if f.Key() == host[0].Key() || f.Fingerprint() == host[0].Fingerprint() {
						t.Fatalf("account result collides with the host summary: %+v", f)
					}
				}
			}
		})
	}
}

func TestWPVerificationCollapsesHostWideFailures(t *testing.T) {
	db := setupPluginStore(t)
	reasons := make(map[string]string, 40)
	for i := range 40 {
		reasons[fmt.Sprintf("/home/alice/site%02d", i)] = "wp-cli executable is unavailable"
	}
	recordWPVerificationFailures(t, db, reasons, "alice")

	findings := wpVerificationFindings(context.Background(), db, "core", "wp_core_verification", nil)
	if len(findings) != 1 {
		t.Fatalf("one host-wide cause produced %d alerts, exhausting the hourly alert budget", len(findings))
	}
	f := findings[0]
	if f.Check != "wp_core_unverified" || f.Severity != alert.Warning {
		t.Fatalf("collapsed coverage gap changed identity: %+v", f)
	}
	if f.FilePath != "" || f.TenantID != "alice" {
		t.Fatalf("single-account summary lost its scope: %+v", f)
	}
	if !strings.Contains(f.Details, "40") || !strings.Contains(f.Details, "wp-cli executable is unavailable") {
		t.Fatalf("collapsed finding hides the scale or the cause: %+v", f)
	}
	if !strings.Contains(f.Details, "/home/alice/site00") || !strings.Contains(f.Details, "more") {
		t.Fatalf("collapsed finding names no examples and no remainder: %+v", f)
	}
}

func TestWPVerificationCollapseScanMergeTransitions(t *testing.T) {
	for _, nc := range []namedCheck{{"wp_core", CheckWPCore}, {"wp_plugin_inventory", CheckWPPluginVerification}} {
		t.Run(nc.name, func(t *testing.T) {
			db := setupPluginStore(t)
			roots, fs := wpCoreQueueFixtures(t, 11)
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			refused := refusedCommand(t)
			recoverLast, recoverAll := false, false
			lastPath := filepath.Dir(roots[10])
			withMockCmd(t, &mockCmd{
				runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
					path := wpCoreQueuePath(t, name, args)
					if recoverAll || (recoverLast && path == lastPath) {
						return []byte("Success: WordPress installation verifies against checksums."), nil
					}
					return []byte("Error: Failed to get core checksums."), refused
				},
				runContextStdout: func(_ context.Context, _ string, args ...string) ([]byte, error) {
					command := strings.Join(args, " ")
					if !strings.Contains(command, "plugin list") {
						return []byte("https://example.test"), nil
					}
					if recoverAll || (recoverLast && strings.Contains(command, lastPath)) {
						return []byte("[]"), nil
					}
					return []byte("PHP Fatal error: configuration failed"), refused
				},
			})
			scan := func(want int, collapsed bool) []alert.Finding {
				t.Helper()
				// Exercise fresh inventory attempts even after partial success.
				if err := db.SetPluginRefreshTime(time.Time{}); err != nil {
					t.Fatal(err)
				}
				ctx, gaps := WithCoverageGaps(context.Background())
				findings, purge := runParallelWithContext(ctx, &config.Config{}, st, []namedCheck{nc}, string(TierDeep), true)
				StoreLatestScanFindingsWithGaps(st, purge, findings, gaps.Paths())
				got := st.LatestFindings()
				if len(got) != want {
					t.Fatalf("latest merge retained the wrong coverage form: got %d, want %d: %+v", len(got), want, got)
				}
				for _, f := range got {
					if (f.FilePath == "") != collapsed {
						t.Fatalf("latest merge retained a stale coverage form: %+v", f)
					}
					if !collapsed && recoverLast && f.FilePath == lastPath {
						t.Fatalf("recovered installation is still unverified: %+v", f)
					}
				}
				return got
			}
			scan(0, false)
			previous := scan(1, true)[0]
			repeated := scan(1, true)[0]
			if previous.Key() != repeated.Key() || previous.Fingerprint() != repeated.Fingerprint() {
				t.Fatal("a repeated collapsed warning creates a new alert")
			}
			// Partial discovery must preserve failures it could not revisit,
			// while allowing successful attempts to clear their warnings.
			originalGlob := fs.glob
			fs.glob = func(pattern string) ([]string, error) {
				paths, _ := originalGlob(pattern)
				return paths, errors.New("fixture incomplete discovery")
			}
			recoverLast = true
			scan(10, false)
			recoverLast = false
			scan(10, false)
			scan(1, true)
			recoverAll = true
			scan(0, false)
		})
	}
}

func TestWPVerificationNamesEachInstallationBelowTheCap(t *testing.T) {
	db := setupPluginStore(t)
	recordWPVerificationFailures(t, db, map[string]string{
		"/home/alice/one": "wp-cli timed out",
		"/home/alice/two": "wp-cli timed out",
	}, "alice")

	findings := wpVerificationFindings(context.Background(), db, "core", "wp_core_verification", nil)
	if len(findings) != 2 {
		t.Fatalf("a handful of failures should still name each installation: %+v", findings)
	}
	for _, f := range findings {
		if f.FilePath == "" || !strings.Contains(f.Message, f.FilePath) {
			t.Fatalf("per-installation finding lost its path: %+v", f)
		}
	}
}

func TestWPVerificationCollapsesEachCauseSeparately(t *testing.T) {
	db := setupPluginStore(t)
	reasons := make(map[string]string, 40)
	for i := range 40 {
		reason := "wp-cli timed out"
		if i%2 == 0 {
			reason = "WordPress could not connect to its database"
		}
		reasons[fmt.Sprintf("/home/alice/site%02d", i)] = reason
	}
	recordWPVerificationFailures(t, db, reasons, "alice")

	findings := wpVerificationFindings(context.Background(), db, "core", "wp_core_verification", nil)
	if len(findings) != 2 {
		t.Fatalf("distinct causes must not share one alert: %+v", findings)
	}
	if findings[0].Key() == findings[1].Key() {
		t.Fatalf("collapsed causes share a dedup identity: %+v", findings)
	}
	for _, f := range findings {
		if !strings.Contains(f.Details, "20") {
			t.Fatalf("collapsed cause hides its count: %+v", f)
		}
	}
}
