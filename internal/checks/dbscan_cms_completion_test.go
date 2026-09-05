package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mysqlclient"
	"github.com/pidginhost/csm/internal/state"
)

type cmsCheckFixture struct {
	name    string
	finding string
	check   CheckFunc
	fs      OS
}

func cmsCheckFixtures() []cmsCheckFixture {
	return []cmsCheckFixture{
		{"joomla", "joomla_content_injection", CheckJoomlaContent, &fakeJoomlaOS{body: canonicalJConfigBody("jos_")}},
		{"drupal", "drupal_content_injection", CheckDrupalContent, &fakeDrupalOS{settingsBody: canonicalDrupalSettings(), hasDrupalPHP: true}},
		{"magento", "magento_content_injection", CheckMagentoContent, &fakeMagentoOS{m2Body: canonicalM2EnvPHP()}},
		{"opencart", "opencart_content_injection", CheckOpenCartContent, &fakeOpenCartOS{rootBody: canonicalOpenCartConfig(), adminBody: canonicalOpenCartConfig()}},
	}
}

func TestCMSQueryFailurePreservesOnlyItsOwnersFindings(t *testing.T) {
	for _, tc := range cmsCheckFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			withCMSConfigOS(t, tc.fs)
			s := newCrontabTestStore(t)
			s.SetLatestFindings([]alert.Finding{
				{Check: tc.finding, Severity: alert.Critical, Message: "prior CMS injection"},
				{Check: "db_post_injection", Severity: alert.Critical, Message: "prior WordPress injection"},
			})
			failed := true
			calls := 0
			mysqlclient.SetPerAccountQueryForTest(func(context.Context, mysqlclient.Creds, string, ...any) ([]string, error) {
				calls++
				if failed {
					return nil, errors.New("database unavailable")
				}
				return nil, nil
			})
			t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
			cmsDone := make(chan struct{})
			checks := []namedCheck{
				{name: "db_content_" + tc.name, fn: func(ctx context.Context, cfg *config.Config, s *state.Store) []alert.Finding {
					defer close(cmsDone)
					return tc.check(ctx, cfg, s)
				}},
				{name: "db_content", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
					<-cmsDone
					return nil
				}},
			}
			findings, purge := runParallel(&config.Config{}, s, checks, "deep", true)
			StoreLatestScanFindings(s, purge, findings)
			got := s.LatestFindings()
			if len(got) != 1 || got[0].Check != tc.finding {
				t.Fatalf("failed CMS and completed WordPress scan retained %+v; want only prior CMS injection", got)
			}
			if calls != 1 {
				t.Errorf("failed installation retried %d queries, want one", calls)
			}
			failed = false
			cmsDone = make(chan struct{})
			findings, purge = runParallel(&config.Config{}, s, checks, "deep", true)
			StoreLatestScanFindings(s, purge, findings)
			if got := s.LatestFindings(); len(got) != 0 {
				t.Fatalf("successful recovery did not clear the old injection: %+v", got)
			}
		})
	}
}

func TestCMSDiscoveryFailureMarksItsOwnerIncomplete(t *testing.T) {
	for _, tc := range cmsCheckFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			withAccountHomeRoots(t, "/home")
			withMockOS(t, &mockOS{glob: func(string) ([]string, error) { return nil, os.ErrPermission }})
			ctx, coverage := withIncompleteCheckCollector(context.Background())
			tc.check(ctx, &config.Config{}, nil)
			if !coverage.contains("db_content_"+tc.name) || coverage.contains("db_content") {
				t.Fatal("failed discovery was treated as an empty, completed CMS scan")
			}
		})
	}
}

func TestCMSDiscoveryRetainsPartialRootFailure(t *testing.T) {
	withAccountHomeRoots(t, "/home", "/srv/accounts")
	withCMSConfigOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.HasPrefix(pattern, "/home/") {
				return nil, os.ErrPermission
			}
			return []string{"/srv/accounts/alice/public_html/configuration.php"}, nil
		},
		readFile: func(string) ([]byte, error) { return []byte(canonicalJConfigBody("jos_")), nil },
	})
	queries := withCapturedQueries(t, func(string) []string { return nil })
	ctx, coverage := withIncompleteCheckCollector(context.Background())
	CheckJoomlaContent(ctx, &config.Config{}, nil)
	if len(*queries) != 3 || !coverage.contains("db_content_joomla") {
		t.Fatalf("partial discovery issued %d queries with incomplete=%t, want three queries and retained coverage gap", len(*queries), coverage.contains("db_content_joomla"))
	}
}

func TestCMSConfigCapDoesNotCompleteCoverage(t *testing.T) {
	withCMSConfigOS(t, &mockOS{
		glob: func(string) ([]string, error) {
			return []string{"/home/alice/public_html/configuration.php", "/home/bob/public_html/configuration.php"}, nil
		},
		readFile: func(string) ([]byte, error) { return []byte(canonicalJConfigBody("jos_")), nil },
	})
	queries := withCapturedQueries(t, func(string) []string { return nil })
	ctx, coverage := withIncompleteCheckCollector(context.Background())
	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 1
	CheckJoomlaContent(ctx, cfg, nil)
	if len(*queries) != 3 || !coverage.contains("db_content_joomla") {
		t.Fatalf("capped discovery issued %d queries with incomplete=%t, want one installation and a coverage gap", len(*queries), coverage.contains("db_content_joomla"))
	}
}

func TestCMSIncompleteAdminQueryDoesNotSeedBaseline(t *testing.T) {
	for _, adapter := range cmsAdminScanners() {
		t.Run(adapter.name, func(t *testing.T) {
			for _, cause := range []string{"overflow", "cancellation", "malformed-row"} {
				t.Run(cause, func(t *testing.T) {
					s := newCrontabTestStore(t)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					ctx, coverage := withIncompleteCheckCollector(ctx)
					rows := []string{"1\tadmin\tadmin@example.test"}
					if cause == "overflow" {
						for id := 2; id <= cmsScanRowLimit+1; id++ {
							rows = append(rows, fmt.Sprintf("%d\tstaff\tstaff@example.test", id))
						}
					}
					if cause == "malformed-row" {
						rows = append(rows, "broken-row")
					}
					queries := withCapturedQueries(t, func(string) []string {
						if cause == "cancellation" {
							cancel()
						}
						return rows
					})
					creds := wpDBCreds{dbHost: "localhost", dbName: "site", tablePrefix: "cms_", queryCtx: ctx}
					adapter.scan(s, "alice", creds)
					if !coverage.contains("db_content_" + adapter.name) {
						t.Error("incomplete administrator query completed the CMS scan")
					}
					creds.queryCtx = context.Background()
					rows = []string{"1\tadmin\tadmin@example.test", "999\tstaff\tstaff@example.test"}
					if got := adapter.scan(s, "alice", creds); len(got) != 0 {
						t.Fatalf("partial query established a baseline before recovery: %+v", got)
					}
					rows = append(rows, "1000\tnew\tnew@example.test")
					if got := adapter.scan(s, "alice", creds); len(got) != 1 || got[0].Severity != alert.High {
						t.Fatalf("complete recovery failed to establish a baseline: %+v", got)
					}
					if len(*queries) != 3 || !strings.HasSuffix((*queries)[0], " LIMIT 201") {
						t.Fatalf("queries did not request bounded overflow evidence: %v", *queries)
					}
				})
			}
		})
	}
}

func TestCMSIncompleteInstallationDoesNotSeedAdminBaseline(t *testing.T) {
	for _, tc := range cmsCheckFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			withCMSConfigOS(t, tc.fs)
			s := newCrontabTestStore(t)
			failed := true
			rows := []string{"1\tadmin\tadmin@example.test"}
			calls := 0
			mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
				calls++
				if failed && calls == 1 {
					return nil, errors.New("content query failed")
				}
				if strings.Contains(query, "username, email") || strings.Contains(query, "u.username, u.email") || strings.Contains(query, "u.uid, u.name, u.mail") {
					return rows, nil
				}
				return nil, nil
			})
			t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
			if got := tc.check(context.Background(), &config.Config{}, s); len(got) != 0 || calls != 1 {
				t.Fatalf("failed installation continued scanning: %+v after %d queries", got, calls)
			}
			failed = false
			rows = append(rows, "2\tstaff\tstaff@example.test")
			if got := tc.check(context.Background(), &config.Config{}, s); len(got) != 0 {
				t.Fatalf("incomplete installation established its administrator baseline: %+v", got)
			}
			rows = append(rows, "3\tnew\tnew@example.test")
			if got := tc.check(context.Background(), &config.Config{}, s); len(got) != 1 || got[0].Check != tc.name+"_admin_injection" {
				t.Fatalf("recovered installation failed to baseline: %+v", got)
			}
		})
	}
}

func TestCMSQueryDetectsOnlyActualOverflow(t *testing.T) {
	for _, count := range []int{0, cmsScanRowLimit, cmsScanRowLimit + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			ctx, coverage := withIncompleteCheckCollector(context.Background())
			rows := make([]string, count)
			for i := range rows {
				rows[i] = fmt.Sprintf("%d\tadmin\tadmin@example.test", i+1)
			}
			withCapturedQueries(t, func(string) []string { return rows })
			got, complete := runCMSQuery(wpDBCreds{queryCtx: ctx, queryOwner: "db_content_joomla"}, "SELECT id FROM users")
			if len(got) != min(count, cmsScanRowLimit) || complete != (count <= cmsScanRowLimit) {
				t.Fatalf("%d-row query returned %d rows, complete=%t", count, len(got), complete)
			}
			if coverage.contains("db_content_joomla") == complete {
				t.Fatal("overflow coverage mark did not match the query result")
			}
		})
	}
}

func TestCMSEmptyAdminQueryEstablishesBaseline(t *testing.T) {
	for _, adapter := range cmsAdminScanners() {
		t.Run(adapter.name, func(t *testing.T) {
			s := newCrontabTestStore(t)
			var rows []string
			withCapturedQueries(t, func(string) []string { return rows })
			creds := wpDBCreds{dbHost: "localhost", dbName: "site", tablePrefix: "cms_"}
			if got := adapter.scan(s, "alice", creds); len(got) != 0 {
				t.Fatalf("empty baseline produced findings: %+v", got)
			}
			rows = []string{"1\tnew\tnew@example.test"}
			if got := adapter.scan(s, "alice", creds); len(got) != 1 || got[0].Severity != alert.High {
				t.Fatalf("first administrator after a complete empty baseline was missed: %+v", got)
			}
		})
	}
}

func TestCMSPartialAdminQueryReportsEachNewIDOnce(t *testing.T) {
	for _, adapter := range cmsAdminScanners() {
		t.Run(adapter.name, func(t *testing.T) {
			s := newCrontabTestStore(t)
			rows := []string{"1\tadmin\tadmin@example.test"}
			withCapturedQueries(t, func(string) []string { return rows })
			creds := wpDBCreds{dbHost: "localhost", dbName: "site", tablePrefix: "cms_"}
			adapter.scan(s, "alice", creds)
			for range cmsScanRowLimit {
				rows = append(rows, "2\tnew\tnew@example.test")
			}
			got := adapter.scan(s, "alice", creds)
			if len(got) != 1 || got[0].Severity != alert.High {
				t.Fatalf("partial administrator result duplicated or hid its new id: %d findings", len(got))
			}
			rows = rows[:2]
			recovered := adapter.scan(s, "alice", creds)
			if len(recovered) != 1 || recovered[0].DedupKey != got[0].DedupKey {
				t.Fatalf("partial query consumed a new id before complete recovery: %+v", recovered)
			}
			if again := adapter.scan(s, "alice", creds); len(again) != 0 {
				t.Fatalf("complete recovery did not remember its new id: %+v", again)
			}
		})
	}
}
