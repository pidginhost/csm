package checks

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func wpConfigBodyFor(db string) string {
	return "<?php\ndefine('DB_NAME', '" + db + "');\ndefine('DB_USER', 'u');\ndefine('DB_PASSWORD', 'p');\ndefine('DB_HOST', 'localhost');\n$table_prefix = 'wp_';\n"
}

// twoInstallWPOS discovers one WordPress install per owner.
func twoInstallWPOS(t *testing.T) *mockOSGlobRoots {
	t.Helper()
	bodies := map[string]string{
		"/home/alice/public_html/wp-config.php": wpConfigBodyFor("alice_db"),
		"/home/bob/public_html/wp-config.php":   wpConfigBodyFor("bob_db"),
	}
	return &mockOSGlobRoots{
		mockOS: mockOS{
			readFile: func(path string) ([]byte, error) {
				if body, ok := bodies[path]; ok {
					return []byte(body), nil
				}
				return nil, os.ErrNotExist
			},
			stat: mtimesByPath(map[string]time.Time{
				"/home/alice/public_html/wp-config.php": time.Now(),
				"/home/bob/public_html/wp-config.php":   time.Now(),
			}),
		},
		files: []string{"/home/alice/public_html/wp-config.php", "/home/bob/public_html/wp-config.php"},
	}
}

// wpProducerNames is the independent fixture inventory for the WordPress
// adapter; it must equal the eligible names owned by db_content.
func wpProducerNames() []string {
	return []string{
		"db_rogue_admin", "db_suspicious_admin_email", "db_siteurl_hijack", "db_siteurl_foreign_host",
		"db_options_injection", "db_options_new_external_script", "db_post_injection", "db_spam_injection",
		"db_spam_found", "db_spam_taxonomy", "db_stored_code_execution", "db_stored_cloak_logic",
		"db_hidden_link_injection", "db_hostname_keyed_option", "db_doorway_sitemap_routes",
		"db_phantom_post_author", "db_post_volume_burst",
	}
}

// ownersFor groups findings by check name and TenantID, asserting that
// every finding's correlation identity is its TenantID.
func ownersFor(t *testing.T, findings []alert.Finding) map[string]map[string]int {
	t.Helper()
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
	return byCheck
}

// Two installs owned by different users in one full scan. The real
// scanner proves the discovery-to-owner path with rogue-admin rows; an
// inert inner scanner proves that every eligible name the adapter owns is
// stamped at the same per-install boundary without last-owner leakage.
func TestWordPressDBProducersStampOwner(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	withCMSConfigOS(t, twoInstallWPOS(t))

	t.Run("real rows", func(t *testing.T) {
		prev := runMySQLQuery
		runMySQLQuery = func(creds wpDBCreds, query string) []string {
			recent := time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
			installed := time.Now().Add(-400 * 24 * time.Hour).Format("2006-01-02 15:04:05")
			switch {
			case strings.Contains(query, "capabilities") && strings.Contains(query, "user_registered"):
				return []string{"7\tintruder\tintruder@example.net\t" + recent + "\t" + installed}
			case strings.Contains(query, "option_name IN"):
				return []string{"siteurl\thttps://example.com/<script src=\"https://203.0.113.6/x.js\"></script>"}
			}
			return nil
		}
		t.Cleanup(func() { runMySQLQuery = prev })
		findings := CheckDatabaseContent(context.Background(), &config.Config{}, newTestStore(t))
		byCheck := ownersFor(t, findings)
		for _, want := range []string{"db_rogue_admin", "db_siteurl_hijack"} {
			if byCheck[want]["alice"] != 1 || byCheck[want]["bob"] != 1 || byCheck[want][""] != 0 {
				t.Errorf("%s owners: %v", want, byCheck[want])
			}
		}
		for _, f := range findings {
			if f.Check == "db_content_scan_incomplete" && f.TenantID != "" {
				t.Errorf("host-wide summary must not carry a tenant: %+v", f)
			}
		}
		res := CorrelateFindings(append([]alert.Finding{critical("db_rogue_admin", "carol")}, findings...))
		if len(res.Derived) != 1 || res.Derived[0].Check != "coordinated_attack" || len(res.Unattributed) != 0 {
			t.Fatalf("emitted output did not aggregate cleanly: %+v", res)
		}
	})

	t.Run("every owned name", func(t *testing.T) {
		prev := wpInstallScanner
		wpInstallScanner = func(_ context.Context, user string, creds wpDBCreds, prefix string) []alert.Finding {
			var out []alert.Finding
			for _, name := range wpProducerNames() {
				out = append(out, alert.Finding{Severity: alert.Critical, Check: name, Message: name + " (account: " + user + ")"})
			}
			return out
		}
		t.Cleanup(func() { wpInstallScanner = prev })
		findings := CheckDatabaseContent(context.Background(), &config.Config{}, newTestStore(t))
		byCheck := ownersFor(t, findings)
		for _, want := range wpProducerNames() {
			if byCheck[want]["alice"] != 1 || byCheck[want]["bob"] != 1 || byCheck[want][""] != 0 {
				t.Errorf("%s owners: %v", want, byCheck[want])
			}
		}
	})
}

func TestWordPressProducerInventoryMatchesRunner(t *testing.T) {
	want := map[string]bool{}
	for _, n := range runnerFindingNames["db_content"] {
		if securityEventEligible(n) {
			want[n] = true
		}
	}
	got := map[string]bool{}
	for _, n := range wpProducerNames() {
		got[n] = true
	}
	for n := range want {
		if !got[n] {
			t.Errorf("eligible db_content name %s has no producer fixture", n)
		}
	}
	for n := range got {
		if !want[n] {
			t.Errorf("fixture names %s, which db_content does not own or is not eligible", n)
		}
	}
}

// Database objects are discovered per WordPress install and stamped with
// that install's owner, including the separate magic-token user findings.
func TestDBObjectProducersStampOwner(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	withCMSConfigOS(t, twoInstallWPOS(t))
	prevObjects, prevTokens := dbObjectScanner, magicTokenScanner
	dbObjectScanner = func(account string, creds wpDBCreds) ([]dbObjectFinding, error) {
		var out []dbObjectFinding
		for _, kind := range []dbObjectKind{dbObjectTrigger, dbObjectFunction, dbObjectProcedure, dbObjectEvent} {
			out = append(out, dbObjectFinding{Account: account, Schema: creds.dbName, Kind: kind, Name: "fixture_" + string(kind), Body: "fixture", IsMalw: true})
		}
		return out, nil
	}
	magicTokenScanner = func(account, schema, tablePrefix string, tokens []string) ([]alert.Finding, error) {
		return []alert.Finding{{Severity: alert.Critical, Check: "db_magic_token_user", Message: "token user in " + schema}}, nil
	}
	t.Cleanup(func() { dbObjectScanner, magicTokenScanner = prevObjects, prevTokens })
	prevTokensOf := magicTokensOf
	magicTokensOf = func(string) []string { return []string{"fixture-token"} }
	t.Cleanup(func() { magicTokensOf = prevTokensOf })

	findings := CheckDatabaseObjects(context.Background(), &config.Config{}, nil)
	byCheck := ownersFor(t, findings)
	for _, want := range []string{"db_malicious_trigger", "db_malicious_function", "db_malicious_procedure", "db_malicious_event", "db_magic_token_user"} {
		if byCheck[want]["alice"] != 1 || byCheck[want]["bob"] != 1 || byCheck[want][""] != 0 {
			t.Errorf("%s owners: %v", want, byCheck[want])
		}
	}
}
