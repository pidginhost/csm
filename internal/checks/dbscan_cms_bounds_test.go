package checks

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The non-WordPress CMS adapters (OpenCart, Joomla, Magento, Drupal) ran
// unbounded content queries, emitted a Warning for every admin row on every
// cycle, discovered installs under public_html only, and issued their
// queries detached from the runner's context.

func withCapturedQueries(t *testing.T, rows func(query string) []string) *[]string {
	t.Helper()
	var queries []string
	old := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		queries = append(queries, query)
		return rows(query)
	}
	t.Cleanup(func() { runMySQLQuery = old })
	return &queries
}

func TestCMSContentQueriesAreBounded(t *testing.T) {
	queries := withCapturedQueries(t, func(string) []string { return nil })
	scanOpenCartSettings("alice", opencartCreds{dbName: "oc", dbPrefix: "oc_"})
	scanOpenCartContentTable("alice", opencartCreds{dbName: "oc", dbPrefix: "oc_"}, "product_description", "description")
	scanJoomlaExtensions("alice", jConfigCreds{dbName: "j"}, "jos_")
	scanJoomlaContent("alice", jConfigCreds{dbName: "j"}, "jos_")
	scanMagentoSettings("alice", magentoCreds{dbName: "m"})
	scanMagentoContent("alice", magentoCreds{dbName: "m"}, "cms_page", "content")
	scanDrupalConfig("alice", drupalCreds{dbName: "d"})
	scanDrupalContent("alice", drupalCreds{dbName: "d"})
	if len(*queries) != 8 {
		t.Fatalf("expected the eight content queries, got %d", len(*queries))
	}
	for _, q := range *queries {
		if !strings.Contains(q, "LIMIT ") {
			t.Errorf("unbounded query: %s", q)
		}
	}
}

func TestCMSAdminScansBaselineThenReportNewAccounts(t *testing.T) {
	store := newCrontabTestStore(t)
	rows := []string{"1\tadmin\tadmin@example.com", "2\tstaff\tstaff@example.com"}
	withCapturedQueries(t, func(string) []string { return rows })
	creds := opencartCreds{dbName: "oc", dbPrefix: "oc_"}

	if got := scanOpenCartAdmins(store, "alice", creds); len(got) != 0 {
		t.Fatalf("first pass must baseline silently, got %+v", got)
	}
	if got := scanOpenCartAdmins(store, "alice", creds); len(got) != 0 {
		t.Fatalf("unchanged admin set must stay quiet, got %+v", got)
	}
	rows = append(rows, "3\thacker\thacker@example.com")
	got := scanOpenCartAdmins(store, "alice", creds)
	if len(got) != 1 {
		t.Fatalf("new admin row not reported: %+v", got)
	}
	if got[0].Severity != alert.High || got[0].Check != "opencart_admin_injection" || !strings.Contains(got[0].Message, "user_id=3") {
		t.Fatalf("finding = %+v, want High opencart_admin_injection naming user_id=3", got[0])
	}
	if again := scanOpenCartAdmins(store, "alice", creds); len(again) != 0 {
		t.Fatalf("an already-reported admin must not repeat every cycle: %+v", again)
	}
}

func TestCMSAdminScansWithoutStoreKeepVisibilityWarnings(t *testing.T) {
	withCapturedQueries(t, func(string) []string { return []string{"1\tadmin\tadmin@example.com"} })
	got := scanOpenCartAdmins(nil, "alice", opencartCreds{dbName: "oc", dbPrefix: "oc_"})
	if len(got) != 1 || got[0].Severity != alert.Warning {
		t.Fatalf("without a store the per-row visibility warning must remain: %+v", got)
	}
}

func TestCMSCredentialsCarryRunnerContext(t *testing.T) {
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "runner")
	if (opencartCreds{ctx: ctx}).asWPDBCreds().queryCtx != ctx {
		t.Error("opencart creds drop the runner context")
	}
	if (jConfigCreds{ctx: ctx}).asWPDBCreds().queryCtx != ctx {
		t.Error("joomla creds drop the runner context")
	}
	if (magentoCreds{ctx: ctx}).asWPDBCreds().queryCtx != ctx {
		t.Error("magento creds drop the runner context")
	}
	if (drupalCreds{ctx: ctx}).asWPDBCreds().queryCtx != ctx {
		t.Error("drupal creds drop the runner context")
	}
}

func TestCMSDiscoveryIncludesAddonDocroots(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	var patterns []string
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			patterns = append(patterns, pattern)
			return nil, nil
		},
		readFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	})
	ctx := context.Background()
	cfg := &config.Config{}
	CheckOpenCartContent(ctx, cfg, nil)
	CheckJoomlaContent(ctx, cfg, nil)
	CheckMagentoContent(ctx, cfg, nil)
	CheckDrupalContent(ctx, cfg, nil)
	for _, want := range []string{
		"/home/*/*/config.php",
		"/home/*/*/configuration.php",
		"/home/*/*/app/etc/env.php",
		"/home/*/*/sites/default/settings.php",
	} {
		if !slices.Contains(patterns, want) {
			t.Errorf("addon docroots not discovered: missing %s in %v", want, patterns)
		}
	}
}
