package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// twoOwnerCMSOS answers discovery globs with one install per owner and
// serves the same configuration body for every configured path.
type twoOwnerCMSOS struct {
	mockOS
	files map[string]string
}

func (m *twoOwnerCMSOS) Glob(pattern string) ([]string, error) {
	base := pattern[strings.LastIndex(pattern, "/")+1:]
	var out []string
	for path := range m.files {
		if strings.HasSuffix(path, "/"+base) && strings.Contains(pattern, "/*") == (strings.Count(path, "/") > 2) {
			out = append(out, path)
		}
	}
	return uniqueStrings(out), nil
}

func (m *twoOwnerCMSOS) ReadFile(name string) ([]byte, error) {
	if body, ok := m.files[name]; ok {
		return []byte(body), nil
	}
	return nil, os.ErrNotExist
}

func (m *twoOwnerCMSOS) Stat(name string) (os.FileInfo, error) {
	if _, ok := m.files[name]; ok {
		return fakeFileInfo{name: name, size: int64(len(m.files[name]))}, nil
	}
	return nil, os.ErrNotExist
}

func (m *twoOwnerCMSOS) Lstat(name string) (os.FileInfo, error) { return m.Stat(name) }

// maliciousRowsFor returns tab-separated rows for one adapter query, keyed on
// the table named in the query. Bodies use the existing inert split token.
func maliciousRowsFor(adapter, query string, pass int) []byte {
	payload := evalToken + "(base64_decode('cGF5bG9hZA=='));"
	admins := "1\tadmin\tadmin@example.com\n"
	if pass == 1 {
		admins += "2\tintruder\tintruder@example.net\n"
	}
	switch adapter {
	case "joomla":
		switch {
		case strings.Contains(query, "extensions"):
			return []byte("system\t" + payload + "\n")
		case strings.Contains(query, "_content"):
			return []byte("42\tWelcome\t<?php " + payload + " ?>\n")
		case strings.Contains(query, "_users"):
			return []byte(admins)
		}
	case "drupal":
		switch {
		case strings.Contains(query, "node_revision__body"):
			return []byte("1\t<?php " + payload + " ?>\n")
		case strings.Contains(query, "users_field_data"):
			return []byte(admins)
		case strings.Contains(query, "config"):
			return []byte("system.site\t" + payload + "\n")
		}
	case "opencart":
		switch {
		case strings.Contains(query, "product_description"), strings.Contains(query, "information_description"):
			return []byte("1\t<?php " + payload + " ?>\n")
		case strings.Contains(query, "setting"):
			return []byte("config_url\t<?php " + payload + " ?>\n")
		case strings.Contains(query, "user"):
			return []byte(admins)
		}
	case "magento":
		switch {
		case strings.Contains(query, "core_config_data"):
			return []byte("web/unsecure/base_url\t<?php " + payload + " ?>\n")
		case strings.Contains(query, "catalog_product_entity_text"), strings.Contains(query, "cms_block"), strings.Contains(query, "cms_page"):
			return []byte("1\t<?php " + payload + " ?>\n")
		case strings.Contains(query, "admin_user"):
			return []byte(admins)
		}
	}
	return nil
}

type cmsAdapterCase struct {
	name  string
	run   func(context.Context, *config.Config, *state.Store) []alert.Finding
	files map[string]string
	want  []string
}

func cmsAdapterCases() []cmsAdapterCase {
	return []cmsAdapterCase{
		{"joomla", CheckJoomlaContent, map[string]string{
			"/home/alice/public_html/configuration.php":         canonicalJConfigBody("jos_"),
			"/var/www/vhosts/bob/public_html/configuration.php": canonicalJConfigBody("jos_"),
		}, []string{"joomla_admin_injection", "joomla_content_injection", "joomla_extensions_injection"}},
		{"drupal", CheckDrupalContent, map[string]string{
			"/home/alice/public_html/sites/default/settings.php":         canonicalDrupalSettings(),
			"/home/alice/public_html/core/lib/Drupal.php":                "<?php // fixture marker",
			"/var/www/vhosts/bob/public_html/sites/default/settings.php": canonicalDrupalSettings(),
			"/var/www/vhosts/bob/public_html/core/lib/Drupal.php":        "<?php // fixture marker",
		}, []string{"drupal_admin_injection", "drupal_content_injection", "drupal_settings_injection"}},
		{"opencart", CheckOpenCartContent, map[string]string{
			"/home/alice/public_html/config.php":               canonicalOpenCartConfig(),
			"/home/alice/public_html/admin/config.php":         canonicalOpenCartConfig(),
			"/var/www/vhosts/bob/public_html/config.php":       canonicalOpenCartConfig(),
			"/var/www/vhosts/bob/public_html/admin/config.php": canonicalOpenCartConfig(),
		}, []string{"opencart_admin_injection", "opencart_content_injection", "opencart_settings_injection"}},
		{"magento", CheckMagentoContent, map[string]string{
			"/home/alice/public_html/app/etc/env.php":           canonicalM2EnvPHP(),
			"/var/www/vhosts/bob/public_html/app/etc/local.xml": canonicalM1XML(),
		}, []string{"magento_admin_injection", "magento_content_injection", "magento_settings_injection"}},
	}
}

// Two installs owned by different users under different account roots: every
// finding of each install carries its own owner, the admin finding appears
// on the pass after the baseline, and the batch correlates by owner.
func TestCMSAdapterProducersStampOwner(t *testing.T) {
	withAccountHomeRoots(t, "/home", "/var/www/vhosts")
	for _, a := range cmsAdapterCases() {
		t.Run(a.name, func(t *testing.T) {
			withCMSConfigOS(t, &twoOwnerCMSOS{files: a.files})
			pass := 0
			withMockCmd(t, &mockCmd{runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
				return maliciousRowsFor(a.name, strings.Join(args, " "), pass), nil
			}})
			st := newTestStore(t)
			_ = a.run(context.Background(), &config.Config{}, st)
			pass = 1
			findings := a.run(context.Background(), &config.Config{}, st)
			byCheck := map[string]map[string]int{}
			for _, f := range findings {
				if byCheck[f.Check] == nil {
					byCheck[f.Check] = map[string]int{}
				}
				byCheck[f.Check][f.TenantID]++
				if got := extractAccountFromFinding(f); got != f.TenantID {
					t.Errorf("%s: correlation account %q != TenantID %q", f.Check, got, f.TenantID)
				}
			}
			for _, want := range a.want {
				if byCheck[want]["alice"] == 0 || byCheck[want]["bob"] == 0 || byCheck[want][""] != 0 {
					t.Errorf("%s owners: %v", want, byCheck[want])
				}
			}
			// Real Critical output crosses the threshold with one anchor owner.
			anchors := []alert.Finding{critical("db_rogue_admin", "carol")}
			res := CorrelateFindings(append(anchors, findings...))
			hasCritical := false
			for _, f := range findings {
				if f.Severity == alert.Critical {
					hasCritical = true
				}
			}
			if hasCritical && (len(res.Derived) != 1 || res.Derived[0].Check != "coordinated_attack") {
				t.Fatalf("critical adapter output did not aggregate: %+v", res)
			}
			if len(res.Unattributed) != 0 {
				t.Fatalf("unattributed rows %v", res.Unattributed)
			}
		})
	}
}

// A configuration outside every account root resolves no owner: TenantID
// stays empty rather than carrying the display label.
func TestCMSAdapterUnresolvedOwnerStaysEmpty(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	withCMSConfigOS(t, &twoOwnerCMSOS{files: map[string]string{"/srv/site/configuration.php": canonicalJConfigBody("jos_")}})
	withMockCmd(t, &mockCmd{runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
		return maliciousRowsFor("joomla", strings.Join(args, " "), 1), nil
	}})
	// cmsDiscover only globs under account roots, so an install outside them
	// is never found; drive the per-install boundary directly.
	findings := scanJoomlaInstall(context.Background(), "/srv/site/configuration.php", newTestStore(t))
	if len(findings) == 0 {
		t.Fatal("fixture produced no findings")
	}
	for _, f := range findings {
		if f.TenantID != "" {
			t.Errorf("unresolved install stamped %q", f.TenantID)
		}
	}
}
