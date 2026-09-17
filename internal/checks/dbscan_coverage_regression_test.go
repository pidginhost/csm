package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/mysqlclient"
)

const databaseScanFallbackDetails = "A document-root record, wp-config.php file, or database query could not be read safely. Findings without complete database coverage are retained."

func databaseCoverageConfig(db string) string {
	return "<?php\ndefine('DB_NAME', '" + db + "');\ndefine('DB_USER', 'fixture');\n$table_prefix = 'wp_';\n"
}

func databaseCoverageHealthyRows(query string) []string {
	// Hidden-link scanning needs the site's address even on a clean database.
	if strings.Contains(query, "'site' AS kind") {
		return []string{"site\tsiteurl\thttps://example.com\t\t19\tsite"}
	}
	return nil
}

func withDatabaseCoverageInstalls(t *testing.T, bodies map[string]string, discoveryErr error) {
	t.Helper()
	withAccountHomeRoots(t, "/home")
	paths := make([]string, 0, len(bodies))
	for path := range bodies {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	withCMSConfigOS(t, &mockOSGlobRoots{
		files: paths,
		mockOS: mockOS{
			readFile: func(path string) ([]byte, error) {
				if body, ok := bodies[path]; ok {
					return []byte(body), nil
				}
				if path == userdataDomainsPath && discoveryErr != nil {
					return nil, discoveryErr
				}
				return nil, os.ErrNotExist
			},
		},
	})
}

func databaseCoverageSummary(t *testing.T, findings []alert.Finding) alert.Finding {
	t.Helper()
	var summaries []alert.Finding
	for _, f := range findings {
		if f.Check == "db_content_scan_incomplete" && f.DedupKey == dbContentHostCoverageDedupKey {
			summaries = append(summaries, f)
		}
	}
	if len(summaries) != 1 {
		t.Fatalf("host-wide summaries = %+v, want exactly one; findings = %+v", summaries, findings)
	}
	f := summaries[0]
	if f.Severity != alert.Warning || f.TenantID != "" || f.FilePath != "" {
		t.Fatalf("host-wide coverage finding has incorrect severity or attribution: %+v", f)
	}
	return f
}

// A config failure must not hide an unreachable database or a partial content
// read. Aliases of a failed database still count as affected installs, but must
// not retry its queries or count each failed query as another install.
func TestDatabaseCoverageMixedReadFailures(t *testing.T) {
	withDatabaseCoverageInstalls(t, map[string]string{
		"/home/alice/public_html/wp-config.php": databaseCoverageConfig("unavailable"),
		"/home/alice/shop/wp-config.php":        databaseCoverageConfig("unavailable"),
		"/home/bob/public_html/wp-config.php":   "<?php\n",
		"/home/carol/public_html/wp-config.php": databaseCoverageConfig("partial"),
		"/home/dora/public_html/wp-config.php":  databaseCoverageConfig("healthy"),
	}, nil)
	failedQueries := 0
	mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, creds mysqlclient.Creds, query string, _ ...any) ([]string, error) {
		if creds.DBName == "unavailable" {
			failedQueries++
			return nil, errors.New("database unavailable")
		}
		if creds.DBName == "partial" && strings.Contains(query, "FROM wp_terms") {
			return []string{"malformed row"}, nil
		}
		return databaseCoverageHealthyRows(query), nil
	})
	t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	ctx, paths := withCoveragePathCollector(ctx)
	f := databaseCoverageSummary(t, CheckDatabaseContent(ctx, nil, nil))
	if !incomplete.contains("db_content") || len(paths.gapPaths("db_content")) != 0 {
		t.Fatal("database gaps must retain pathless findings through whole-check preservation")
	}
	if failedQueries != 1 {
		t.Errorf("failed database queried %d times, want once across both installs", failedQueries)
	}
	want := "4 of 5 discovered installs could not be fully inspected.\n" +
		"incomplete_content=1 (example: /home/carol/public_html/wp-config.php)\n" +
		"missing_credentials=1 (example: /home/bob/public_html/wp-config.php)\n" +
		"query_failed=2 (example: /home/alice/public_html/wp-config.php)\n" +
		"Query failures: stage=options class=unknown code=0 queries=1\n" +
		"Findings without complete database coverage are retained."
	if f.Details != want {
		t.Errorf("details = %q, want %q", f.Details, want)
	}
}

func TestDatabaseCoveragePartialDiscovery(t *testing.T) {
	withDatabaseCoverageInstalls(t, map[string]string{
		"/home/alice/public_html/wp-config.php": "<?php\n",
	}, os.ErrPermission)
	ctx, _ := withIncompleteCheckCollector(context.Background())
	f := databaseCoverageSummary(t, CheckDatabaseContent(ctx, nil, nil))
	for _, want := range []string{"1 of 1", "missing_credentials=1", "Document-root discovery was incomplete; additional installs may be missing."} {
		if !strings.Contains(f.Details, want) {
			t.Errorf("details omit %q: %q", want, f.Details)
		}
	}
}

func TestDatabaseCoverageContentOnly(t *testing.T) {
	for _, reason := range []string{"query_failed", "incomplete_content"} {
		t.Run(reason, func(t *testing.T) {
			withDatabaseCoverageInstalls(t, map[string]string{
				"/home/alice/public_html/wp-config.php": databaseCoverageConfig("partial"),
			}, nil)
			mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
				if strings.Contains(query, "FROM wp_terms") {
					if reason == "query_failed" {
						return nil, errors.New("query failed")
					}
					return []string{"malformed row"}, nil
				}
				return databaseCoverageHealthyRows(query), nil
			})
			t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
			ctx, incomplete := withIncompleteCheckCollector(context.Background())
			f := databaseCoverageSummary(t, CheckDatabaseContent(ctx, nil, nil))
			if !incomplete.contains("db_content") || !strings.Contains(f.Details, reason+"=1") || !strings.HasPrefix(f.Details, "1 of 1") {
				t.Fatalf("content gap must propagate to the whole check and name its install: %+v", f)
			}
		})
	}
}

func TestDatabaseCoverageFallback(t *testing.T) {
	for _, discovered := range []bool{false, true} {
		t.Run(fmt.Sprintf("discovered=%t", discovered), func(t *testing.T) {
			bodies := map[string]string{}
			if discovered {
				bodies["/home/alice/public_html/wp-config.php"] = databaseCoverageConfig("healthy")
			}
			withDatabaseCoverageInstalls(t, bodies, os.ErrPermission)
			mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
				return databaseCoverageHealthyRows(query), nil
			})
			t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
			ctx, incomplete := withIncompleteCheckCollector(context.Background())
			f := databaseCoverageSummary(t, CheckDatabaseContent(ctx, nil, nil))
			if !incomplete.contains("db_content") || f.Details != databaseScanFallbackDetails {
				t.Fatalf("zero attributed reasons must retain the generic fallback: %+v", f)
			}
		})
	}
}

// The network limit has its own account-specific warning. It must neither be
// counted again in the aggregate nor suppress another install's config gap.
func TestDatabaseCoverageMultisiteLimit(t *testing.T) {
	for _, missingConfig := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing_config=%t", missingConfig), func(t *testing.T) {
			bodies := map[string]string{
				"/home/alice/public_html/wp-config.php": databaseCoverageConfig("network") + "define('MULTISITE', true);\n",
			}
			if missingConfig {
				bodies["/home/bob/public_html/wp-config.php"] = "<?php\n"
			}
			withDatabaseCoverageInstalls(t, bodies, nil)
			mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
				if strings.Contains(query, "FROM wp_blogs") {
					rows := make([]string, maxWPSecondaryBlogs+1)
					for i := range rows {
						rows[i] = fmt.Sprint(i + 2)
					}
					return rows, nil
				}
				return databaseCoverageHealthyRows(query), nil
			})
			t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
			ctx, incomplete := withIncompleteCheckCollector(context.Background())
			findings := CheckDatabaseContent(ctx, nil, nil)
			if !incomplete.contains("db_content") {
				t.Fatal("multisite limit lost whole-check preservation")
			}
			limits := 0
			for _, f := range findings {
				if f.Check == "db_content_scan_incomplete" && f.DedupKey != dbContentHostCoverageDedupKey {
					limits++
					if f.TenantID != "alice" || !strings.Contains(f.Message, fmt.Sprintf("%d-site safety limit (account: alice)", maxWPSecondaryBlogs)) {
						t.Errorf("multisite warning lost its account or limit: %+v", f)
					}
				}
			}
			if limits != 1 {
				t.Errorf("multisite limit warnings = %d, want one", limits)
			}
			if !missingConfig {
				if len(findings) != 1 {
					t.Fatalf("multisite limit reported more than once: %+v", findings)
				}
				return
			}
			if len(findings) != 2 {
				t.Fatalf("want a limit warning and a separate config summary: %+v", findings)
			}
			f := databaseCoverageSummary(t, findings)
			if !strings.HasPrefix(f.Details, "1 of 2") || !strings.Contains(f.Details, "missing_credentials=1") || strings.Contains(f.Details, "incomplete_content") {
				t.Errorf("summary suppressed the config failure or double-counted the network: %q", f.Details)
			}
		})
	}
}

func TestDatabaseCoverageBoundedExamples(t *testing.T) {
	path := "/home/alice/" + strings.Repeat("a", 220) + "/wp-config.php"
	withDatabaseCoverageInstalls(t, map[string]string{path: "<?php\n"}, nil)
	ctx, _ := withIncompleteCheckCollector(context.Background())
	f := databaseCoverageSummary(t, CheckDatabaseContent(ctx, nil, nil))
	if !strings.Contains(f.Details, "example: "+path[:200]+"...)") || strings.Contains(f.Details, path) {
		t.Fatalf("example path must keep its existing truncation bound: %q", f.Details)
	}
}

func TestDatabaseCoverageCompleteScan(t *testing.T) {
	for _, discovered := range []bool{false, true} {
		t.Run(fmt.Sprintf("discovered=%t", discovered), func(t *testing.T) {
			bodies := map[string]string{}
			if discovered {
				bodies["/home/alice/public_html/wp-config.php"] = databaseCoverageConfig("healthy")
			}
			withDatabaseCoverageInstalls(t, bodies, nil)
			mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
				return databaseCoverageHealthyRows(query), nil
			})
			t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
			ctx, incomplete := withIncompleteCheckCollector(context.Background())
			findings := CheckDatabaseContent(ctx, nil, nil)
			if incomplete.contains("db_content") || len(findings) != 0 {
				t.Fatalf("complete clean scan reported a gap: %+v", findings)
			}
		})
	}
}
