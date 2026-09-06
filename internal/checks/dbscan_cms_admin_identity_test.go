package checks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/mysqlclient"
	"github.com/pidginhost/csm/internal/state"
)

type cmsAdminScanner struct {
	name string
	scan func(*state.Store, string, wpDBCreds) []alert.Finding
}

func cmsAdminScanners() []cmsAdminScanner {
	return []cmsAdminScanner{
		{"joomla", func(s *state.Store, account string, c wpDBCreds) []alert.Finding {
			return scanJoomlaSuperUsers(s, account, jConfigCreds{ctx: c.queryCtx, dbHost: c.dbHost, dbName: c.dbName}, c.tablePrefix)
		}},
		{"drupal", func(s *state.Store, account string, c wpDBCreds) []alert.Finding {
			return scanDrupalAdmins(s, account, drupalCreds{ctx: c.queryCtx, dbHost: c.dbHost, dbName: c.dbName})
		}},
		{"magento", func(s *state.Store, account string, c wpDBCreds) []alert.Finding {
			return scanMagentoAdmins(s, account, magentoCreds{ctx: c.queryCtx, dbHost: c.dbHost, dbName: c.dbName, dbPrefix: c.tablePrefix})
		}},
		{"opencart", func(s *state.Store, account string, c wpDBCreds) []alert.Finding {
			return scanOpenCartAdmins(s, account, opencartCreds{ctx: c.queryCtx, dbHost: c.dbHost, dbName: c.dbName, dbPrefix: c.tablePrefix})
		}},
	}
}

func TestCMSAdminBaselinesArePerInstallation(t *testing.T) {
	for _, adapter := range cmsAdminScanners() {
		t.Run(adapter.name, func(t *testing.T) {
			for _, dimension := range []string{"database", "host", "account", "prefix"} {
				if adapter.name == "drupal" && dimension == "prefix" {
					continue // The Drupal adapter scans unprefixed tables only.
				}
				t.Run(dimension, func(t *testing.T) {
					s := newCrontabTestStore(t)
					first := wpDBCreds{dbHost: "localhost", dbName: "site", tablePrefix: "cms_"}
					second := first
					secondAccount := "alice"
					switch dimension {
					case "database":
						second.dbName = "other_site"
					case "host":
						second.dbHost = "other-db.example.test"
					case "account":
						secondAccount = "bob"
					case "prefix":
						second.tablePrefix = "other_"
					}
					rows := []string{"1\tadmin\tadmin@example.test"}
					withCapturedQueries(t, func(string) []string { return rows })
					if got := adapter.scan(s, "alice", first); len(got) != 0 {
						t.Fatalf("first installation baseline = %+v", got)
					}
					rows = []string{"2\tstaff\tstaff@example.test"}
					if got := adapter.scan(s, secondAccount, second); len(got) != 0 {
						t.Errorf("second installation's existing administrator was reported as new: %+v", got)
					}
					rows = append(rows, "1\tadmin\tadmin@example.test")
					got := adapter.scan(s, secondAccount, second)
					if len(got) != 1 || got[0].Severity != alert.High || !strings.Contains(got[0].Details, "Row: 1\t") {
						t.Fatalf("administrator id already present in another installation was missed: %+v", got)
					}
					if again := adapter.scan(s, secondAccount, second); len(again) != 0 {
						t.Fatalf("unchanged administrators repeated: %+v", again)
					}
				})
			}
		})
	}
}

func TestCMSAdminMigrationDoesNotTrustAccountWideKeys(t *testing.T) {
	for _, adapter := range cmsAdminScanners() {
		t.Run(adapter.name, func(t *testing.T) {
			s := newCrontabTestStore(t)
			s.SetRaw("_cmsadmin_baseline:"+adapter.name+":alice", "1")
			s.SetRaw("_cmsadmin:"+adapter.name+":alice:9", "seen")
			rows := []string{"1\tadmin\tadmin@example.test"}
			withCapturedQueries(t, func(string) []string { return rows })
			creds := wpDBCreds{dbHost: "localhost", dbName: "site", tablePrefix: "cms_"}
			if got := adapter.scan(s, "alice", creds); len(got) != 0 {
				t.Errorf("migration reported existing administrators: %+v", got)
			}
			rows = append(rows, "9\tnew\tnew@example.test")
			if got := adapter.scan(s, "alice", creds); len(got) != 1 || got[0].Severity != alert.High {
				t.Fatalf("ambiguous old key suppressed a new administrator: %+v", got)
			}
		})
	}
}

func TestCMSAdminFindingsKeepInstallationIdentity(t *testing.T) {
	for _, adapter := range cmsAdminScanners() {
		t.Run(adapter.name, func(t *testing.T) {
			s := newCrontabTestStore(t)
			rows := []string{"1\tadmin\tadmin@example.test"}
			withCapturedQueries(t, func(string) []string { return rows })
			first := wpDBCreds{dbHost: "localhost", dbName: "site_one", tablePrefix: "cms_"}
			second := first
			second.dbName = "site_two"
			adapter.scan(s, "alice", first)
			adapter.scan(s, "alice", second)
			rows = append(rows, "9\tnew\tnew@example.test")
			one, two := adapter.scan(s, "alice", first), adapter.scan(s, "alice", second)
			if len(one) != 1 || len(two) != 1 {
				t.Fatalf("same new id in two installations must produce two findings: %+v, %+v", one, two)
			}
			if one[0].DedupKey == "" || one[0].DedupKey == two[0].DedupKey {
				t.Fatal("finding identity omitted the installation")
			}
			if !strings.Contains(one[0].Details, "Database: site_one") || !strings.Contains(two[0].Details, "Database: site_two") {
				t.Fatal("findings do not identify the affected database")
			}
		})
	}
}

func TestCMSAdminFailedQueryDoesNotSeedBaseline(t *testing.T) {
	for _, adapter := range cmsAdminScanners() {
		t.Run(adapter.name, func(t *testing.T) {
			s := newCrontabTestStore(t)
			rows := []string{"1\tadmin\tadmin@example.test"}
			queryErr := errors.New("database unavailable")
			calls := 0
			mysqlclient.SetPerAccountQueryForTest(func(context.Context, mysqlclient.Creds, string, ...any) ([]string, error) {
				calls++
				return rows, queryErr
			})
			t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
			creds := wpDBCreds{dbHost: "localhost", dbName: "site", tablePrefix: "cms_"}
			if got := adapter.scan(s, "alice", creds); len(got) != 0 {
				t.Fatalf("failed query produced findings: %+v", got)
			}
			queryErr = nil
			rows = append(rows, "2\tstaff\tstaff@example.test")
			if got := adapter.scan(s, "alice", creds); len(got) != 0 {
				t.Fatalf("failed query established a partial baseline: %+v", got)
			}
			rows = append(rows, "3\tnew\tnew@example.test")
			if got := adapter.scan(s, "alice", creds); len(got) != 1 || calls != 3 {
				t.Fatalf("recovered scan did not establish its baseline: %+v after %d queries", got, calls)
			}
		})
	}
}
