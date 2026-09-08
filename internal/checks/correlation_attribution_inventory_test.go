package checks

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// attributionEvidence maps every newly eligible check (eligible minus the
// legacy baseline) to the test that proves its producer supplies an account
// identity, or to the registry gap it carries. Adding an eligible check
// without a decision here fails.
var attributionEvidence = map[string]string{
	// Database content, WordPress adapter.
	"db_doorway_sitemap_routes":      "TestWordPressDBProducersStampOwner",
	"db_hidden_link_injection":       "TestWordPressDBProducersStampOwner",
	"db_hostname_keyed_option":       "TestWordPressDBProducersStampOwner",
	"db_options_injection":           "TestWordPressDBProducersStampOwner",
	"db_options_new_external_script": "TestWordPressDBProducersStampOwner",
	"db_phantom_post_author":         "TestWordPressDBProducersStampOwner",
	"db_post_injection":              "TestWordPressDBProducersStampOwner",
	"db_post_volume_burst":           "TestWordPressDBProducersStampOwner",
	"db_rogue_admin":                 "TestWordPressDBProducersStampOwner",
	"db_siteurl_foreign_host":        "TestWordPressDBProducersStampOwner",
	"db_siteurl_hijack":              "TestWordPressDBProducersStampOwner",
	"db_spam_found":                  "TestWordPressDBProducersStampOwner",
	"db_spam_injection":              "TestWordPressDBProducersStampOwner",
	"db_spam_taxonomy":               "TestWordPressDBProducersStampOwner",
	"db_stored_cloak_logic":          "TestWordPressDBProducersStampOwner",
	"db_stored_code_execution":       "TestWordPressDBProducersStampOwner",
	"db_suspicious_admin_email":      "TestWordPressDBProducersStampOwner",
	// Database objects.
	"db_magic_token_user":    "TestDBObjectProducersStampOwner",
	"db_malicious_event":     "TestDBObjectProducersStampOwner",
	"db_malicious_function":  "TestDBObjectProducersStampOwner",
	"db_malicious_procedure": "TestDBObjectProducersStampOwner",
	"db_malicious_trigger":   "TestDBObjectProducersStampOwner",
	// Other CMS adapters.
	"joomla_admin_injection":      "TestCMSAdapterProducersStampOwner",
	"joomla_content_injection":    "TestCMSAdapterProducersStampOwner",
	"joomla_extensions_injection": "TestCMSAdapterProducersStampOwner",
	"drupal_admin_injection":      "TestCMSAdapterProducersStampOwner",
	"drupal_content_injection":    "TestCMSAdapterProducersStampOwner",
	"drupal_settings_injection":   "TestCMSAdapterProducersStampOwner",
	"opencart_admin_injection":    "TestCMSAdapterProducersStampOwner",
	"opencart_content_injection":  "TestCMSAdapterProducersStampOwner",
	"opencart_settings_injection": "TestCMSAdapterProducersStampOwner",
	"magento_admin_injection":     "TestCMSAdapterProducersStampOwner",
	"magento_content_injection":   "TestCMSAdapterProducersStampOwner",
	"magento_settings_injection":  "TestCMSAdapterProducersStampOwner",
	// Crontab.
	"suspicious_crontab": "TestSuspiciousCrontabStampsSpoolOwner",
	// Mail producers.
	"mail_per_account":           "TestMailPerAccountLeavesSenderAggregateUnattributed",
	"email_pipe_forwarder":       "TestForwarderFindingsStampOwner",
	"email_suspicious_forwarder": "TestForwarderFindingsStampOwner",
	"email_filter_blackhole":     "TestMailFilterFindingsAttributeByPath",
	"email_filter_exfil":         "TestMailFilterFindingsAttributeByPath",
	"email_filter_forwarder":     "TestMailFilterFindingsAttributeByPath",
	"email_filter_pipe":          "TestMailFilterFindingsAttributeByPath",
	"email_compromised_account":  "TestWatcherMailFindingsStampOwner",
	"email_credential_leak":      "TestWatcherMailFindingsStampOwner",
	"email_spam_outbreak":        "TestWatcherMailFindingsStampOwner",
	"email_rate_critical":        "TestWatcherMailFindingsStampOwner",
	"email_rate_warning":         "TestWatcherMailFindingsStampOwner",
	"mail_account_compromised":   "TestMailBruteCompromiseStampsOwner",
	"email_php_relay_abuse":      "TestPHPRelayAbuseStampsOwner",
	"email_cloud_relay_abuse":    "TestCloudRelayFindingCarriesTenant",
	"email_suspicious_geo":       "TestDovecotGeoFindingCarriesTenant",
	// Path-bearing scheduled file families.
	"phishing_credential_log":       "TestPhishingFindingsAttributeByPath",
	"phishing_directory":            "TestPhishingFindingsAttributeByPath",
	"phishing_iframe":               "TestPhishingFindingsAttributeByPath",
	"phishing_kit_archive":          "TestPhishingFindingsAttributeByPath",
	"phishing_page":                 "TestPhishingFindingsAttributeByPath",
	"phishing_php":                  "TestPhishingFindingsAttributeByPath",
	"phishing_redirector":           "TestPhishingFindingsAttributeByPath",
	"htaccess_auto_prepend":         "TestHtaccessFindingsAttributeByPath",
	"htaccess_cgi_handler_abuse":    "TestHtaccessFindingsAttributeByPath",
	"htaccess_errordocument_hijack": "TestHtaccessFindingsAttributeByPath",
	"htaccess_filesmatch_shield":    "TestHtaccessFindingsAttributeByPath",
	"htaccess_handler_abuse":        "TestHtaccessFindingsAttributeByPath",
	"htaccess_header_injection":     "TestHtaccessFindingsAttributeByPath",
	"htaccess_injection":            "TestHtaccessFindingsAttributeByPath",
	"htaccess_php_in_uploads":       "TestHtaccessFindingsAttributeByPath",
	"htaccess_security_disabled":    "TestHtaccessFindingsAttributeByPath",
	"htaccess_spam_redirect":        "TestHtaccessFindingsAttributeByPath",
	"htaccess_user_agent_cloak":     "TestHtaccessFindingsAttributeByPath",
	"new_php_in_sensitive_dir":      "TestFileIndexFindingsAttributeByPath",
	"new_suspicious_php":            "TestFileIndexFindingsAttributeByPath",
	"suid_binary":                   "TestFilesystemFindingsAttributeByPath",
	"suspicious_php_content":        "TestContentFindingsAttributeByPath",
	"php_remote_taint":              "TestContentFindingsAttributeByPath",
	"js_keylogger_dataflow":         "TestContentFindingsAttributeByPath",
	"yara_match_scheduled":          "TestYARAScheduledFindingAttributesByPath",
	"wp_core_integrity":             "TestWPCoreIntegrityAttributesByPath",
	"symlink_attack":                "TestSymlinkAttackStampsOwner",
	// Realtime producers (Linux).
	"cgi_backdoor_realtime":            "TestFanotifyFindingsAttributeByPath",
	"cgi_suspicious_location_realtime": "TestFanotifyFindingsAttributeByPath",
	"credential_log_realtime":          "TestFanotifyFindingsAttributeByPath",
	"executable_in_tmp_realtime":       "TestFanotifyFindingsAttributeByPath",
	"htaccess_injection_realtime":      "TestFanotifyFindingsAttributeByPath",
	"phishing_kit_realtime":            "TestFanotifyFindingsAttributeByPath",
	"phishing_realtime":                "TestFanotifyFindingsAttributeByPath",
	"php_dropper_realtime":             "TestFanotifyFindingsAttributeByPath",
	"signature_match_realtime":         "TestFanotifyFindingsAttributeByPath",
	"yara_match_realtime":              "TestYARARealtimeFindingAttributesByPath",
	"self_deleting_dropper_realtime":   "TestDropperEngineFindingAttributesByPath",
	"php_shield_block":                 "TestPHPShieldFindingsStampOwner",
	"php_shield_eval":                  "TestPHPShieldFindingsStampOwner",
	"php_shield_webshell":              "TestPHPShieldFindingsStampOwner",
	// Process and login producers.
	"exfiltration_paste_site":      "TestExfiltrationFindingStampsOwner",
	"af_alg_socket_use":            "TestAFALGFindingStampsOwner",
	"cpanel_file_upload":           "TestCPanelLoginFindingsStampOwner",
	"cpanel_multi_ip_login":        "TestCPanelLoginFindingsStampOwner",
	"ftp_login_after_bruteforce":   "TestFTPLoginAfterBruteforceStampsOwner",
	"password_hijack_confirmed":    "TestPasswordHijackFindingsCarryTenant",
	"whm_password_change_noninfra": "TestPasswordHijackFindingsCarryTenant",
	"direct_smtp_egress":           "TestDirectSMTPEgressCarriesTenant",
	// Documented gaps (registry CorrelationGap).
	"backdoor_port":          "gap:" + gapSocketOwner,
	"backdoor_port_outbound": "gap:" + gapSocketOwner,
	"bad_asn_outbound":       "gap:" + gapPartialSocketOwner,
}

func newlyEligibleChecks() map[string]CheckInfo {
	baseline := map[string]bool{}
	for _, n := range legacyEligibleBaseline {
		baseline[n] = true
	}
	out := map[string]CheckInfo{}
	for _, c := range checkRegistry {
		if securityEventEligible(c.Name) && !baseline[c.Name] {
			out[c.Name] = c
		}
	}
	return out
}

func compareAttributionInventory(evidence map[string]string, newly map[string]CheckInfo) []string {
	var problems []string
	for name, c := range newly {
		ev, ok := evidence[name]
		switch {
		case !ok:
			problems = append(problems, name+": newly eligible without an attribution decision")
		case strings.HasPrefix(ev, "gap:"):
			if c.CorrelationGap != strings.TrimPrefix(ev, "gap:") {
				problems = append(problems, name+": inventory gap "+ev+" disagrees with registry gap "+c.CorrelationGap)
			}
		case c.CorrelationGap != "":
			problems = append(problems, name+": registry declares gap "+c.CorrelationGap+" but inventory names a producer test")
		case !strings.HasPrefix(ev, "Test"):
			problems = append(problems, name+": evidence "+ev+" is neither a test name nor a gap")
		}
	}
	for name := range evidence {
		if _, ok := newly[name]; !ok {
			problems = append(problems, name+": listed but not newly eligible")
		}
	}
	sort.Strings(problems)
	return problems
}

func TestAttributionInventoryCoversNewlyEligible(t *testing.T) {
	newly := newlyEligibleChecks()
	if len(newly) == 0 {
		t.Fatal("no newly eligible checks; the registry classification is missing")
	}
	if problems := compareAttributionInventory(attributionEvidence, newly); len(problems) != 0 {
		t.Fatalf("attribution inventory drift:\n  %s", strings.Join(problems, "\n  "))
	}
	// Negative controls on copies: removal, addition and a misassigned gap
	// each produce a diagnostic naming the check.
	removed := map[string]string{}
	for k, v := range attributionEvidence {
		removed[k] = v
	}
	delete(removed, "db_rogue_admin")
	if p := compareAttributionInventory(removed, newly); len(p) != 1 || !strings.HasPrefix(p[0], "db_rogue_admin:") {
		t.Fatalf("removal not diagnosed: %v", p)
	}
	added := map[string]string{}
	for k, v := range attributionEvidence {
		added[k] = v
	}
	added["ip_reputation"] = "TestNothing"
	if p := compareAttributionInventory(added, newly); len(p) != 1 || !strings.HasPrefix(p[0], "ip_reputation:") {
		t.Fatalf("extra entry not diagnosed: %v", p)
	}
	wrongGap := map[string]string{}
	for k, v := range attributionEvidence {
		wrongGap[k] = v
	}
	wrongGap["backdoor_port"] = "gap:" + gapPartialSocketOwner
	wrongGap["suspicious_crontab"] = "gap:" + gapSocketOwner
	if p := compareAttributionInventory(wrongGap, newly); len(p) != 2 {
		t.Fatalf("misassigned gaps not diagnosed: %v", p)
	}
}

// repoRootFromSource locates the repository from this file's own location,
// so the scan does not depend on the process working directory.
func repoRootFromSource(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok || !filepath.IsAbs(here) {
		return findRepoRoot(t)
	}
	for dir := filepath.Dir(here); ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		if filepath.Dir(dir) == dir {
			t.Fatalf("go.mod not found above %s", here)
		}
	}
}

// testDeclarations parses every _test.go file under internal/ and returns
// each Test function name with its file and build constraint. Parsing, not
// a regex, so a name inside a comment or string does not count.
func testDeclarations(t *testing.T) map[string]struct{ file, constraint string } {
	t.Helper()
	root := filepath.Join(repoRootFromSource(t), "internal")
	out := map[string]struct{ file, constraint string }{}
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			return perr
		}
		constraint := ""
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if strings.HasPrefix(c.Text, "//go:build ") {
					constraint = strings.TrimPrefix(c.Text, "//go:build ")
				}
			}
			if cg.End() >= f.Package {
				break
			}
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			rel, _ := filepath.Rel(root, path)
			out[fn.Name.Name] = struct{ file, constraint string }{rel, constraint}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Every named producer test must be a real declaration. YARA-backed tests
// must live behind the yara build constraint under their own names so they
// are never silently compiled out under a shared name.
func TestAttributionEvidenceTestsExist(t *testing.T) {
	declared := testDeclarations(t)
	for name, ev := range attributionEvidence {
		if strings.HasPrefix(ev, "gap:") {
			continue
		}
		decl, ok := declared[ev]
		if !ok {
			t.Errorf("%s: producer test %s is not declared under internal/", name, ev)
			continue
		}
		if strings.Contains(ev, "YARA") && !strings.Contains(decl.constraint, "yara") {
			t.Errorf("%s: %s must be behind the yara build constraint (found %q in %s)", name, ev, decl.constraint, decl.file)
		}
	}
}
