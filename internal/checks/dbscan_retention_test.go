package checks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mysqlclient"
	"github.com/pidginhost/csm/internal/state"
)

func TestDatabaseCompletedInstallRetiresOnlyItsFindings(t *testing.T) {
	withDatabaseCoverageInstalls(t, map[string]string{
		"/home/alice/public_html/wp-config.php": databaseCoverageConfig("healthy"),
		"/home/alice/shop/wp-config.php":        databaseCoverageConfig("failed"),
	}, nil)
	clean := false
	mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, creds mysqlclient.Creds, query string, _ ...any) ([]string, error) {
		if clean && creds.DBName == "failed" {
			return nil, errors.New("unavailable")
		}
		if !clean && strings.Contains(query, "FROM wp_terms") {
			return []string{"1\tcategory\t1\thttps://example.com"}, nil
		}
		return databaseCoverageHealthyRows(query), nil
	})
	t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	run := func() {
		ctx, gaps := WithCoverageGaps(context.Background())
		findings, purge := runParallelWithContext(ctx, &config.Config{}, nil, []namedCheck{{name: "db_content", fn: CheckDatabaseContent}}, "test", true)
		StoreLatestScanFindingsWithCoverage(st, purge, findings, gaps.Snapshot())
	}
	run()
	var old []alert.Finding
	for _, f := range st.LatestFindings() {
		if f.Check == "db_spam_taxonomy" {
			old = append(old, f)
		}
	}
	if len(old) != 2 {
		t.Fatalf("initial detections = %d, want 2", len(old))
	}
	// Pre-upgrade records cannot be attributed to a database safely. Preserve
	// them while coverage is incomplete, without guessing from display text.
	legacy := alert.Finding{Check: "db_spam_taxonomy", DedupKey: "legacy", Severity: alert.High, Message: "older detection"}
	st.PurgeAndMergeFindings(nil, []alert.Finding{legacy})
	clean = true
	run()
	keys := make(map[string]bool)
	for _, f := range st.LatestFindings() {
		keys[f.Key()] = true
	}
	for _, f := range old {
		want := strings.Contains(f.Details, "Database: failed\n")
		if keys[f.Key()] != want {
			t.Errorf("retained %q = %t, want %t", f.Details, keys[f.Key()], want)
		}
	}
	if !keys[legacy.Key()] {
		t.Fatal("unscoped legacy finding retired during incomplete coverage")
	}
}

func TestDatabaseIncompleteMultisiteDoesNotPublishScope(t *testing.T) {
	for _, kind := range []string{"limit", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			withDatabaseCoverageInstalls(t, map[string]string{
				"/home/alice/public_html/wp-config.php": databaseCoverageConfig("network") + "define('MULTISITE', true);\n",
			}, nil)
			mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
				if strings.Contains(query, "FROM wp_blogs") {
					if kind == "malformed" {
						return []string{"invalid"}, nil
					}
					rows := make([]string, maxWPSecondaryBlogs+1)
					for i := range rows {
						rows[i] = fmt.Sprint(i + 2)
					}
					return rows, nil
				}
				return databaseCoverageHealthyRows(query), nil
			})
			t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
			ctx, gaps := WithCoverageGaps(context.Background())
			findings, purge := runParallelWithContext(ctx, &config.Config{}, nil, []namedCheck{{name: "db_content", fn: CheckDatabaseContent}}, "test", true)
			if !containsFindingCheck(findings, "db_content_scan_incomplete") || len(gaps.Snapshot().CompletedScopes) != 0 {
				t.Fatalf("incomplete network published complete coverage: findings=%+v scopes=%v", findings, gaps.Snapshot().CompletedScopes)
			}
			for _, name := range purge {
				if name == "db_post_injection" {
					t.Fatal("incomplete network authorized whole-owner purge")
				}
			}
		})
	}
}

func TestRunnerDiscardsScopesAfterTimeout(t *testing.T) {
	previous := timeoutForFunc
	timeoutForFunc = func(string) time.Duration { return 25 * time.Millisecond }
	t.Cleanup(func() { timeoutForFunc = previous })
	ctx, gaps := WithCoverageGaps(context.Background())
	finished := make(chan struct{})
	_, _ = runParallelWithContext(ctx, &config.Config{}, nil, []namedCheck{{name: "db_content", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		defer close(finished)
		recordCompletedCoverageScopes(ctx, "db_content", map[string]bool{"partial": true})
		<-ctx.Done()
		return nil
	}}}, "test", true)
	<-finished
	if len(gaps.Snapshot().CompletedScopes) != 0 {
		t.Fatal("timed-out check published retirement scopes")
	}
}

func TestDatabaseWhollyIncompleteScanRetainsFindingsAtCap(t *testing.T) {
	for _, failure := range []string{"query", "config", "discovery"} {
		t.Run(failure, func(t *testing.T) {
			bodies := map[string]string{
				"/home/alice/public_html/wp-config.php": databaseCoverageConfig("site"),
			}
			var discoveryErr error
			if failure == "config" {
				bodies["/home/alice/public_html/wp-config.php"] = "<?php\n"
			}
			if failure == "discovery" {
				bodies = nil
				discoveryErr = errors.New("discovery unavailable")
			}
			withDatabaseCoverageInstalls(t, bodies, discoveryErr)
			mysqlclient.SetPerAccountQueryForTest(func(context.Context, mysqlclient.Creds, string, ...any) ([]string, error) {
				return nil, errors.New("database unavailable")
			})
			t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			old := []alert.Finding{
				{Check: "db_post_injection", DedupKey: "scoped", CoverageScope: "unread", Severity: alert.Warning, Timestamp: time.Unix(100, 0)},
				{Check: "db_post_injection", DedupKey: "legacy", Severity: alert.Warning, Timestamp: time.Unix(100, 0)},
			}
			st.PurgeAndMergeFindings(nil, old)
			ctx, gaps := WithCoverageGaps(context.Background())
			findings, purge := runParallelWithContext(ctx, &config.Config{}, nil, []namedCheck{
				{name: "db_content", fn: CheckDatabaseContent},
				{name: "other", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
					// Exceed the active-set cap with independent, higher-priority findings.
					fresh := make([]alert.Finding, 16000)
					for i := range fresh {
						fresh[i] = alert.Finding{Check: "other", DedupKey: fmt.Sprint(i), Severity: alert.High}
					}
					return fresh
				}},
			}, "test", true)
			StoreLatestScanFindingsWithCoverage(st, purge, findings, gaps.Snapshot())
			retained := make(map[string]alert.Finding)
			for _, f := range st.LatestFindings() {
				retained[f.Key()] = f
			}
			for _, f := range old {
				got, ok := retained[f.Key()]
				if !ok || got.CoverageScope != f.CoverageScope || !got.FirstSeen.Equal(f.Timestamp) {
					t.Errorf("incomplete scan lost prior finding %q or its observation: %+v", f.DedupKey, got)
				}
			}
		})
	}
}

func TestInterruptedDatabaseScanRetainsFindingsAtCap(t *testing.T) {
	for _, failure := range []string{"timeout", "panic"} {
		t.Run(failure, func(t *testing.T) {
			previous := timeoutForFunc
			timeoutForFunc = func(name string) time.Duration {
				if name == "db_content" {
					return 25 * time.Millisecond
				}
				return previous(name)
			}
			t.Cleanup(func() { timeoutForFunc = previous })
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			old := []alert.Finding{
				{Check: "db_post_injection", DedupKey: "scoped", CoverageScope: "unread", Severity: alert.Warning, Timestamp: time.Unix(100, 0)},
				{Check: "db_post_injection", DedupKey: "legacy", Severity: alert.Warning, Timestamp: time.Unix(100, 0)},
			}
			st.PurgeAndMergeFindings(nil, old)
			finished := make(chan struct{})
			ctx, gaps := WithCoverageGaps(context.Background())
			findings, purge := runParallelWithContext(ctx, &config.Config{}, nil, []namedCheck{
				{name: "db_content", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
					defer close(finished)
					if failure == "panic" {
						panic("scanner failure")
					}
					<-ctx.Done()
					return nil
				}},
				{name: "other", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
					fresh := make([]alert.Finding, 16000)
					for i := range fresh {
						fresh[i] = alert.Finding{Check: "other", DedupKey: fmt.Sprint(i), Severity: alert.High}
					}
					return fresh
				}},
			}, "test", true)
			<-finished
			StoreLatestScanFindingsWithCoverage(st, purge, findings, gaps.Snapshot())
			retained := make(map[string]alert.Finding)
			for _, f := range st.LatestFindings() {
				retained[f.Key()] = f
			}
			for _, f := range old {
				got, ok := retained[f.Key()]
				if !ok || got.CoverageScope != f.CoverageScope || !got.FirstSeen.Equal(f.Timestamp) {
					t.Errorf("interrupted scan lost prior finding %q or its observation: %+v", f.DedupKey, got)
				}
			}
		})
	}
}
