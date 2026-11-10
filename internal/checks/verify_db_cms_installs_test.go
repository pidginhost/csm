package checks

import (
	"context"
	"maps"
	"sort"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

// cmsTwoInstallCase is one CMS with installs in bob's public_html (database
// <name>_db) and in the addon folder shop2 (database <name>_db2).
type cmsTwoInstallCase struct {
	name     string
	files    map[string]string
	statOK   map[string]bool
	verifies []cmsCase
	// admin is an administrator finding recorded in shop2's database.
	admin  cmsCase
	prefix string
	// db is the public_html install's database; shop2 uses db + "2".
	db string
}

func cmsTwoInstallCases() []cmsTwoInstallCase {
	drupalFiles2, drupalStat := drupalFiles()
	drupalFiles2["/home/bob/shop2/sites/default/settings.php"] = strings.Replace(drupalSettings, "'drupal_db'", "'drupal_db2'", 1)
	drupalStat["/home/bob/shop2/core/lib/Drupal.php"] = true
	joomla := joomlaFiles()
	joomla["/home/bob/shop2/configuration.php"] = strings.Replace(joomlaConfig, "'joomla_db'", "'joomla_db2'", 1)
	magento := magentoFiles()
	magento["/home/bob/shop2/app/etc/env.php"] = strings.Replace(magentoEnv, "'magento_db'", "'magento_db2'", 1)
	opencart := opencartFiles()
	opencart["/home/bob/shop2/config.php"] = strings.Replace(opencartConfig, "'oc_db'", "'oc_db2'", 1)
	opencart["/home/bob/shop2/admin/config.php"] = opencart["/home/bob/shop2/config.php"]
	return []cmsTwoInstallCase{
		{name: "drupal", db: "drupal_db", files: drupalFiles2, statOK: drupalStat, prefix: "", verifies: []cmsCase{
			{name: "settings", verify: verifyDrupalSettingsInjection, details: "Account: bob\nConfig name: system.site"},
			{name: "content", verify: verifyDrupalContentInjection, details: "Account: bob\nNode entity_id: 7"},
		}, admin: cmsCase{name: "admin", verify: verifyDrupalAdminInjection, details: "Account: bob\nRow: 42\tadmin\tx@example.test"}},
		{name: "joomla", db: "joomla_db", files: joomla, prefix: "jos_", verifies: []cmsCase{
			{name: "extensions", verify: verifyJoomlaExtensionsInjection, details: "Account: bob\nExtension: plg_fixture"},
			{name: "content", verify: verifyJoomlaContentInjection, details: "Account: bob\nArticle ID: 7"},
		}, admin: cmsCase{name: "admin", verify: verifyJoomlaAdminInjection, details: "Account: bob\nRow: 7\tadmin\tx@example.test"}},
		{name: "magento", db: "magento_db", files: magento, prefix: "", verifies: []cmsCase{
			{name: "settings", verify: verifyMagentoSettingsInjection, details: "Account: bob\nConfig path: web/unsecure/base_url"},
			{name: "content", verify: verifyMagentoContentInjection, details: "Account: bob\nTable: cms_page\nRow id: 3"},
		}, admin: cmsCase{name: "admin", verify: verifyMagentoAdminInjection, details: "Account: bob\nRow: 3\tadmin\tx@example.test"}},
		{name: "opencart", db: "oc_db", files: opencart, prefix: "oc_", verifies: []cmsCase{
			{name: "settings", verify: verifyOpenCartSettingsInjection, details: "Account: bob\nSetting key: config_url"},
			{name: "content", verify: verifyOpenCartContentInjection, details: "Account: bob\nTable: product_description\nRow id: 9"},
		}, admin: cmsCase{name: "admin", verify: verifyOpenCartAdminInjection, details: "Account: bob\nRow: 9\tadmin\tx@example.test"}},
	}
}

// withRecheckQueries serves per-install queries through fn and makes any root
// query return a clean result, so a re-check that still queried as root would
// wrongly resolve rather than error.
func withRecheckQueries(t *testing.T, fn func(c mysqlclient.Creds, query string, args ...any) ([]string, error)) {
	t.Helper()
	mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, c mysqlclient.Creds, query string, args ...any) ([]string, error) {
		return fn(c, query, args...)
	})
	t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
	withRootQuery(t, func(string, string, ...any) ([]string, error) { return nil, nil })
}

func TestCMSRecheckChecksEveryInstall(t *testing.T) {
	for _, tc := range cmsTwoInstallCases() {
		for _, c := range tc.verifies {
			t.Run(tc.name+"/"+c.name, func(t *testing.T) {
				withCMSVerifyOS(t, tc.files, tc.statOK)
				withRecheckQueries(t, func(creds mysqlclient.Creds, _ string, _ ...any) ([]string, error) {
					if strings.HasSuffix(creds.DBName, "_db2") {
						return []string{"bad eval(base64_decode($x))"}, nil
					}
					return nil, nil
				})
				if res := c.verify("", c.details); !res.Checked || res.Resolved {
					t.Fatalf("addon install still injected, result %+v, want unresolved", res)
				}
			})
		}
	}
}

func TestCMSRecheckResolvesWhenEveryInstallIsClean(t *testing.T) {
	for _, tc := range cmsTwoInstallCases() {
		for _, c := range tc.verifies {
			t.Run(tc.name+"/"+c.name, func(t *testing.T) {
				withCMSVerifyOS(t, tc.files, tc.statOK)
				queried := map[string]bool{}
				withRecheckQueries(t, func(creds mysqlclient.Creds, _ string, _ ...any) ([]string, error) {
					if creds.User == "" || creds.Host != "localhost" {
						t.Errorf("query for %s ran without the install's login: user %q host %q", creds.DBName, creds.User, creds.Host)
					}
					queried[creds.DBName] = true
					return nil, nil
				})
				if res := c.verify("", c.details); !res.Checked || !res.Resolved {
					t.Fatalf("result %+v, want resolved", res)
				}
				got := make([]string, 0, len(queried))
				for db := range queried {
					got = append(got, db)
				}
				sort.Strings(got)
				if want := tc.db + "," + tc.db + "2"; strings.Join(got, ",") != want {
					t.Fatalf("queried %v, want both installs %s", got, want)
				}
			})
		}
	}
}

func TestCMSRecheckUnreadableInstallStaysUnchecked(t *testing.T) {
	for _, tc := range cmsTwoInstallCases() {
		for _, c := range tc.verifies {
			t.Run(tc.name+"/"+c.name, func(t *testing.T) {
				files := maps.Clone(tc.files)
				withCMSConfigOS(t, &cmsVerifyOS{files: files, statOK: tc.statOK, unreadable: "/home/bob/shop2/"})
				withRecheckQueries(t, func(mysqlclient.Creds, string, ...any) ([]string, error) { return nil, nil })
				if res := c.verify("", c.details); res.Checked {
					t.Fatalf("an unreadable install was skipped: %+v", res)
				}
			})
		}
	}
}

func cmsRecordedDetails(db, prefix, rest string) string {
	return "Database: " + db + "\nTable prefix: " + prefix + "\nDatabase host: localhost\n" + rest
}

func TestCMSAdminRecheckUsesRecordedDatabase(t *testing.T) {
	for _, tc := range cmsTwoInstallCases() {
		t.Run(tc.name, func(t *testing.T) {
			withCMSVerifyOS(t, tc.files, tc.statOK)
			db2 := tc.db + "2"
			var queried []string
			withRecheckQueries(t, func(creds mysqlclient.Creds, _ string, _ ...any) ([]string, error) {
				queried = append(queried, creds.DBName)
				return nil, nil
			})
			res := tc.admin.verify("", cmsRecordedDetails(db2, tc.prefix, tc.admin.details))
			if !res.Checked || !res.Resolved || strings.Join(queried, ",") != db2 {
				t.Fatalf("result %+v after querying %v, want resolved in %s only", res, queried, db2)
			}
			queried = nil
			if res := tc.admin.verify("", cmsRecordedDetails("other_db", tc.prefix, tc.admin.details)); res.Checked || len(queried) != 0 {
				t.Fatalf("finding for a database on no install = %+v after %v, want unchecked", res, queried)
			}
		})
	}
}

func TestPrestaShopRecheckFindsAddonShop(t *testing.T) {
	withCMSVerifyOS(t, prestashopInstallFiles("/home/bob/shop2", "ps_"), nil)
	withRecheckQueries(t, func(mysqlclient.Creds, string, ...any) ([]string, error) { return nil, nil })
	res := verifyPrestaShopSettingsInjection("", psVerifyDetails("Account: bob\nSetting id: 12"))
	if !res.Checked || !res.Resolved {
		t.Fatalf("addon shop finding = %+v, want checked and resolved", res)
	}
}
