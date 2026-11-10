package checks

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// A suspended account's database user is locked: its installs are skipped
// without leaving the check incomplete, and other accounts are still scanned.
func TestCMSScansSkipSuspendedAccounts(t *testing.T) {
	withAccountHomeRoots(t, "/home", "/var/www/vhosts")
	for _, a := range cmsAdapterCases() {
		for _, suspended := range []string{"alice", "bob", "both"} {
			t.Run(a.name+"/"+suspended, func(t *testing.T) {
				files := maps.Clone(a.files)
				active := "bob"
				if suspended == "bob" {
					active = "alice"
				}
				var suspendedHomes []string
				for account, home := range map[string]string{"alice": "/home/alice/", "bob": "/var/www/vhosts/bob/"} {
					if suspended == account || suspended == "both" {
						files["/var/cpanel/suspended/"+account] = ""
						suspendedHomes = append(suspendedHomes, home)
					}
				}
				base := &twoOwnerCMSOS{files: files}
				withCMSConfigOS(t, &mockOS{
					glob: func(pattern string) ([]string, error) {
						var paths []string
						for path := range files {
							matched, err := filepath.Match(pattern, path)
							if err != nil {
								return nil, err
							}
							if matched {
								paths = append(paths, path)
							}
						}
						slices.Sort(paths)
						return paths, nil
					},
					readFile: func(path string) ([]byte, error) {
						for _, home := range suspendedHomes {
							if strings.HasPrefix(path, home) {
								t.Errorf("read suspended account configuration: %s", path)
								return nil, os.ErrPermission
							}
						}
						return base.ReadFile(path)
					},
					stat:  base.Stat,
					lstat: base.Lstat,
				})
				queries := 0
				withMockCmd(t, &mockCmd{runWithEnv: func(_ string, args []string, _ ...string) ([]byte, error) {
					queries++
					return maliciousRowsFor(a.name, strings.Join(args, " "), 0), nil
				}})
				ctx, coverage := withIncompleteCheckCollector(context.Background())
				cfg := &config.Config{}
				cfg.Thresholds.AccountScanMaxFiles = 1
				findings := a.run(ctx, cfg, nil)
				byCheck := map[string]int{}
				for _, f := range findings {
					if f.TenantID != active || suspended == "both" {
						t.Errorf("unexpected tenant %q for %s", f.TenantID, f.Check)
					}
					byCheck[f.Check]++
				}
				want := map[string]int{}
				if suspended != "both" {
					for _, check := range a.want {
						want[check] = 1
					}
					switch a.name {
					case "opencart":
						want["opencart_content_injection"] = 2
					case "magento", "prestashop":
						want[a.name+"_content_injection"] = 3
					}
				} else if queries != 0 {
					t.Errorf("all accounts suspended, but ran %d queries", queries)
				}
				if !maps.Equal(byCheck, want) {
					t.Errorf("findings by check = %v, want %v", byCheck, want)
				}
				if coverage.contains("db_content_" + a.name) {
					t.Error("skipping a suspended account left the check incomplete")
				}
			})
		}
	}
}

func TestCMSDropSuspendedKeepsUnownedPaths(t *testing.T) {
	withAccountHomeRoots(t, "/home", "/var/www/vhosts")
	withMockOS(t, &twoOwnerCMSOS{files: map[string]string{
		"/var/cpanel/suspended/alice": "",
	}})
	paths := []string{
		"/home/alice/public_html/configuration.php",
		"/srv/alice/public_html/configuration.php",
		"/home2/alice/public_html/configuration.php",
		"/var/www/vhosts/bob/public_html/configuration.php",
		"/var/www/vhosts/alice/public_html/configuration.php",
	}
	want := slices.Clone(paths[1:4])
	if got := cmsDropSuspended(paths); !slices.Equal(got, want) {
		t.Fatalf("eligible configurations = %v, want %v", got, want)
	}
}
