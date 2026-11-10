package checks

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/mysqlclient"
)

func writeCMSVerifyFiles(t *testing.T, home string, files map[string]string, markers map[string]bool) {
	t.Helper()
	write := func(name, body string) {
		path := filepath.Join(home, strings.TrimPrefix(name, "/home/bob/"))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range files {
		write(name, body)
	}
	for name := range markers {
		write(name, "<?php")
	}
}

// filepath.Glob suppresses ELOOP just as it suppresses permission and I/O
// errors. A clean visible site cannot vouch for an inaccessible addon.
func TestCMSRecheckDiscoveryErrorsStayUnchecked(t *testing.T) {
	cases := cmsTwoInstallCases()
	cases = append(cases, cmsTwoInstallCase{
		name: "prestashop", db: "shop_db", prefix: "ps_", files: prestashopVerifyFiles(),
		verifies: []cmsCase{{name: "settings", verify: verifyPrestaShopSettingsInjection,
			details: psVerifyDetails("Account: bob\nSetting id: 12")}},
		admin: cmsCase{name: "admin", verify: verifyPrestaShopAdminInjection, details: "Account: bob\nRow: 9\t1\tstaff@example.test"},
	})
	for _, tc := range cases {
		for _, nested := range []bool{false, true} {
			t.Run(tc.name+"/nested="+strconv.FormatBool(nested), func(t *testing.T) {
				root := t.TempDir()
				home := filepath.Join(root, "bob")
				files := map[string]string{}
				for path, body := range tc.files {
					if strings.Contains(path, "/public_html/") {
						files[path] = body
					}
				}
				markers := map[string]bool{}
				for path := range tc.statOK {
					if strings.Contains(path, "/public_html/") {
						markers[path] = true
					}
				}
				writeCMSVerifyFiles(t, home, files, markers)
				link := filepath.Join(home, "shop2")
				if nested {
					child := map[string]string{"drupal": "sites", "joomla": "configuration.php", "magento": "app", "opencart": "config.php", "prestashop": "config"}[tc.name]
					if err := os.Mkdir(link, 0o755); err != nil {
						t.Fatal(err)
					}
					link = filepath.Join(link, child)
				}
				if err := os.Symlink(filepath.Base(link), link); err != nil {
					t.Fatal(err)
				}
				withMockOS(t, realOS{})
				withAccountHomeRoots(t, root)
				queries := 0
				withRecheckQueries(t, func(mysqlclient.Creds, string, ...any) ([]string, error) {
					queries++
					return nil, nil
				})
				checks := append([]cmsCase{}, tc.verifies...)
				admin := tc.admin
				admin.details = cmsRecordedDetails(tc.db, tc.prefix, admin.details)
				checks = append(checks, admin)
				for _, c := range checks {
					if res := c.verify("", c.details); res.Checked || res.Resolved {
						t.Errorf("%s: inaccessible addon was skipped: %+v", c.name, res)
					}
				}
				if queries != 0 {
					t.Errorf("incomplete discovery reached %d queries", queries)
				}
			})
		}
	}
}

func TestCMSRecheckLaterQueryErrorStaysUnchecked(t *testing.T) {
	for _, tc := range cmsTwoInstallCases() {
		for _, c := range tc.verifies {
			t.Run(tc.name+"/"+c.name, func(t *testing.T) {
				withCMSVerifyOS(t, tc.files, tc.statOK)
				calls := 0
				withRecheckQueries(t, func(creds mysqlclient.Creds, _ string, _ ...any) ([]string, error) {
					calls++
					if creds.DBName == tc.db {
						return []string{"bad eval(base64_decode($x))"}, nil
					}
					return nil, context.DeadlineExceeded
				})
				if res := c.verify("", c.details); res.Checked || res.Resolved || calls != 2 {
					t.Fatalf("later query failure: result=%+v calls=%d, want unchecked after both queries", res, calls)
				}
			})
		}
	}
}

type cmsVerifyReadDirErrorOS struct {
	realOS
}

func (o cmsVerifyReadDirErrorOS) ReadDir(path string) ([]os.DirEntry, error) {
	entries, _ := o.realOS.ReadDir(path)
	return entries, os.ErrPermission
}

func TestCMSRecheckRejectsPartialHomeInventory(t *testing.T) {
	root := t.TempDir()
	writeCMSVerifyFiles(t, filepath.Join(root, "bob"), joomlaFiles(), nil)
	withAccountHomeRoots(t, root)
	withMockOS(t, cmsVerifyReadDirErrorOS{})
	withRecheckQueries(t, func(mysqlclient.Creds, string, ...any) ([]string, error) {
		t.Fatal("partial home inventory reached a query")
		return nil, nil
	})
	if res := verifyJoomlaContentInjection("", "Account: bob\nArticle ID: 7"); res.Checked || res.Resolved {
		t.Fatalf("partial home inventory: %+v, want unchecked", res)
	}
}

func TestCMSRecheckPartitionedHomeAndLinkedFolders(t *testing.T) {
	for _, tc := range cmsTwoInstallCases() {
		t.Run(tc.name, func(t *testing.T) {
			base := withPartitionedAccounts(t, "bob:x:1001:1001::BASE/home2/bob:/bin/bash\n", "bob")
			home := filepath.Join(base, "home2", "bob")
			writeCMSVerifyFiles(t, home, tc.files, tc.statOK)
			if err := os.Symlink("public_html", filepath.Join(home, "www")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, "notes.txt"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("notes.txt", filepath.Join(home, "notes-link")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(home, "empty"), 0o755); err != nil {
				t.Fatal(err)
			}
			queried := map[string]int{}
			withRecheckQueries(t, func(creds mysqlclient.Creds, _ string, _ ...any) ([]string, error) {
				queried[creds.DBName]++
				return nil, nil
			})
			c := tc.verifies[0]
			if res := c.verify("", c.details); !res.Checked || !res.Resolved {
				t.Fatalf("partitioned account with linked folders: %+v", res)
			}
			if len(queried) != 2 || queried[tc.db] != 1 || queried[tc.db+"2"] != 1 {
				t.Fatalf("queries = %v, want both databases exactly once", queried)
			}
		})
	}
}

func TestMagentoRecheckSelectsVersionPerFolder(t *testing.T) {
	files := magentoFiles()
	files["/home/bob/public_html/app/etc/local.xml"] = strings.ReplaceAll(canonicalM1XML(), "magento_db", "stale_db")
	files["/home/bob/shop2/app/etc/local.xml"] = strings.ReplaceAll(canonicalM1XML(), "magento_db", "legacy_db")
	withCMSVerifyOS(t, files, nil)
	queried := map[string]string{}
	withRecheckQueries(t, func(creds mysqlclient.Creds, query string, _ ...any) ([]string, error) {
		queried[creds.DBName] = query
		return nil, nil
	})
	if res := verifyMagentoSettingsInjection("", "Account: bob\nConfig path: web/unsecure/base_url"); !res.Checked || !res.Resolved {
		t.Fatalf("mixed Magento versions: %+v", res)
	}
	if len(queried) != 2 || !strings.Contains(queried["magento_db"], "`core_config_data`") || !strings.Contains(queried["legacy_db"], "`m1_core_config_data`") {
		t.Fatalf("queries = %v, want current main and legacy addon only", queried)
	}
}

func TestCMSAdminDefaultPrefixRoundTrip(t *testing.T) {
	for _, cms := range []string{"joomla", "opencart"} {
		t.Run(cms, func(t *testing.T) {
			files, prefix := joomlaFiles(), "jos_"
			verify := verifyJoomlaAdminInjection
			scan := func() []alert.Finding {
				return scanJoomlaInstall(context.Background(), "/home/bob/public_html/configuration.php", nil)
			}
			if cms == "opencart" {
				files, prefix = opencartFiles(), "oc_"
				verify = verifyOpenCartAdminInjection
				scan = func() []alert.Finding {
					return scanOpenCartInstall(context.Background(), "/home/bob/public_html/config.php", nil)
				}
			}
			for path, body := range files {
				files[path] = strings.ReplaceAll(body, "'"+prefix+"'", "''")
			}
			withCMSVerifyOS(t, files, nil)
			withCapturedQueries(t, func(query string) []string {
				if strings.Contains(query, "username") {
					return []string{"7\tfixture\tstaff@example.test"}
				}
				return nil
			})
			findings := scan()
			if len(findings) != 1 || detailField(findings[0].Details, "Table prefix") != prefix {
				t.Fatal("scanner did not record the effective default prefix")
			}
			calls := 0
			withRecheckQueries(t, func(_ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
				calls++
				if !strings.Contains(query, "`"+prefix+"user") {
					t.Fatalf("query lost the recorded prefix: %s", query)
				}
				return nil, nil
			})
			if res := verify(findings[0].Message, findings[0].Details); !res.Checked || !res.Resolved || calls != 1 {
				t.Fatalf("default prefix re-check: %+v, queries=%d", res, calls)
			}
		})
	}
}

// A link left behind by a removed site points nowhere and holds no install;
// it must not make every re-check on the account unchecked.
func TestCMSRecheckIgnoresDanglingHomeLinks(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "bob")
	writeCMSVerifyFiles(t, home, joomlaFiles(), nil)
	if err := os.Symlink(filepath.Join(home, "removed-site"), filepath.Join(home, "old-site")); err != nil {
		t.Fatal(err)
	}
	withAccountHomeRoots(t, root)
	withRecheckQueries(t, func(mysqlclient.Creds, string, ...any) ([]string, error) { return nil, nil })
	if res := verifyJoomlaContentInjection("", "Account: bob\nArticle ID: 7"); !res.Checked || !res.Resolved {
		t.Fatalf("dangling home link: %+v, want checked and resolved", res)
	}
}
