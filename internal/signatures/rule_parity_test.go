package signatures

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// realtimeOnlyRules lists every rule that exists in malware.yml with no
// same-name rule in malware.yar, together with why it has not been ported.
//
// Scans run YARA-X only; the pure-Go .yml engine is reachable from realtime
// fanotify and finding re-check alone. Most entries are therefore invisible to
// `csm scan` and to files already sitting on disk. Entries marked as renames
// already run under another YARA rule ID and stay here to prevent double ports.
//
// Tier and policy labels carry two kinds of evidence and both are needed.
// Corpus and live measurement find what the sample contains; a hand-written
// benign control finds what it does not. Rules measured silent on 15,992 clean
// files and on a 291k-file live sample still fire on ordinary plugin code that
// neither sample happens to include, so "silent" alone is not a porting
// licence.
//
// This map may only shrink.
var realtimeOnlyRules = map[string]string{
	"backdoor_cron_reverse_shell":      "Rename, not a gap: byte-identical regex already ships as backdoor_cron_downloader, so the detection runs on every scan. Porting it would double-report",
	"backdoor_php_auto_append":         "Tier 2: htaccess-scoped; the directive also appears as a string literal in security-plugin PHP, giving 7 port-induced live hits",
	"backdoor_systemd_service":         "Tier 2: min_match 1 with a single generic literal (the ExecStart directive) and require_regex false, so the regex is decorative and ANY systemd unit satisfies the rule. Caught by a benign-unit control sample, not by corpus measurement",
	"backdoor_wp_muplugin_loader":      "Rename, not a gap: the decoded-include arm already ships under backdoor_wp_muplugin. The narrower case-insensitive variant belongs in that rule to avoid double-reporting",
	"cgi_bash_webshell":                "Rename, and the .yar side is the HARDENED one: cgi_webshell_bash requires the bash shebang at offset 0, which is what keeps the four bare substrings from matching any large bundle. Porting this .yml version by name would replace a hardened rule with the weak original",
	"cgi_haxor_extension":              "Tier 2: content signal is the literal shebang, which occurs by chance in binary; 473 live hits across 22 file types including .jpg, .pdf, .zip and fonts. Real detection is the .haxor filename and belongs in internal/checks",
	"credential_logger":                "Tier 2: measured at 1 hit on the clean corpus, on security-plugin login code, and it also fires on a newsletter opt-in handler writing a sanitized posted address to a log file. Redesign before porting",
	"credential_mailer":                "Tier 2: already a live realtime false positive on Elementor and WooCommerce registration mail, measured at 4 hits on the clean corpus. credential_harvester_php covers the shape, but its variable-name proximity arm is evaded by short names; harden that rule instead of porting this one",
	"dropper_php_stream_wrapper":       "Rename, not a gap: dropper_stream_wrapper_abuse carries the same three wrapper arms and still fires on a require/zip:// variant sharing no literal with the sample that first matched",
	"dropper_wp_plugin_installer":      "Tier 1: silent on the corpus, on a 291k-file live sample, and on a benign control (a plugin writing its own compiled template cache). Ready to port",
	"exfil_wp_config_reader":           "Tier 2: silent on both samples, yet fires on an authenticated migration job staging wp-config for its export package. Redesign before porting",
	"exploit_cpanel_api_abuse":         "Tier 2: silent on both samples, yet fires on a vendor SDK helper building a cPanel session URL. Redesign before porting",
	"exploit_htaccess_handler":         "Rename, not a gap: exploit_htaccess_handler_abuse covers every extension form this rule does, in both engines, pinned by the behavioural samples",
	"exploit_php_fpm_rce":              "Tier 1: silent on the corpus, on a 291k-file live sample, and on a benign control (a deployment tool building fastcgi params). Ready to port",
	"exploit_wp_fake_plugin_installer": "Tier 1: silent on both samples, and the control written for it turned out to be the dropper behaviour the rule targets, not a false positive. No benign control has been found yet, so the porting case rests on measurement alone",
	"exploit_wp_options_inject":        "Tier 2: silent on both samples, yet fires on a site-address settings screen guarded by a capability check and a nonce. Redesign before porting",
	"exploit_wp_rest_api":              "Tier 2: 29 port-induced live hits, every one on a .mo translation catalogue",
	"exploit_wp_xmlrpc":                "Rename, not a gap: identical regexes already ship as exploit_wp_xmlrpc_abuse",
	"gsocket_persistence":              "Rename, not a gap: the same two persistence markers already ship as gsocket_cron_persistence",
	"mailer_bombermail":                "Tier 2: silent on both samples, yet fires on a malware scanner's mail-bomb signature catalogue without any mail-sending behavior. Redesign before porting",
	"mailer_exim_exploit":              "Tier 2: 268 port-induced live hits, almost all on plugin .js assets; also already a live realtime false positive on the PHPMailer SMTP class in WordPress core",
	"mailer_phpmailer_abuse":           "Tier 1: silent on the corpus, on a 291k-file live sample, and on a benign control (a mailer addressed from a stored option). Ready to port",
	"miner_coinhive_js":                "Rename, not a gap: identical regexes already ship as miner_coinhive",
	"miner_cryptoloot_js":              "Rename, not a gap: miner_cryptoloot covers the same case-insensitive brand token and hyphenated domain; the Anonymous arm is subsumed by the brand token in both engines",
	"miner_monero_wallet":              "Tier 2: silent on both samples, yet fires on a project support page showing a donation address. Redesign before porting",
	"miner_shell_script":               "Rename, not a gap: miner_shell_downloader matches the same downloader-to-miner span in either case now that its case gap is closed",
	"network_brute_force":              "Covered and HARDENED under another name: network_brute_force_tool requires the connection in the same loop span as either the credential-list header or a list-consuming operation. This .yml form is bare co-occurrence and fires when an FTP plugin defines separate stored-password and connection helpers",
	"network_http_tunnel":              "Tier 2: port-induced hit on plugin .js; also already a live realtime false positive on the FTP sockets class in WordPress core",
	"obfuscation_assert_string":        "Rename, not a gap: the same three assert input forms already ship as obfuscation_assert_exec",
	"obfuscation_create_function":      "Tier 2: 4 port-induced live hits on plugin readme .txt; also already a live realtime false positive",
	"obfuscation_ionCube_fake":         "Tier 2: min_match 2 with two ionCube brand literals, so a legitimate loader stub fires it without the regex ever matching. Commercial encoded PHP is absent from the corpus, so measurement alone missed this",
	"phishing_dhl_fedex":               "Tier 2: silent on both samples, yet fires on ordinary shipping-plugin copy that mentions delivery notifications and tracking numbers without a brand or credential form. Redesign before porting",
	"phishing_google_drive":            "Tier 2: silent on both samples, yet fires on a Drive backup plugin settings screen that names the product, links to accounts.google.com for authorisation, and takes a service-account key in a password field. Redesign before porting",
	"phishing_onedrive":                "Tier 2: already fires in realtime on live data. phishing_sharepoint covers the brand but requires a form action attribute, so a kit submitting through JavaScript evades it. Harden that rule; this .yml form asks only for two brand words beside any typed input",
	"phishing_webmail":                 "Policy finding: stock Roundcube templates use dynamic login objects, not a rendered password form. A standalone rendered clone in an account document root is phishing-shaped. Ready to port",
	"phishing_workers_dev_exfil":       "Tier 2: silent on both samples, yet fires on a site whose own API is hosted on Cloudflare Workers. Redesign before porting",
	"php_dropper_gist":                 "Covered and HARDENED under another name: php_dropper_github_gist requires the gist URL plus an execution sink, while this .yml form fires on the bare URL at min_match 1. Porting it by name would weaken the shipped rule and double-report",
	"php_dropper_raw_github":           "Tier 1: two of its four arms already ship as dropper_fgc_eval and dropper_rfi_include. The remaining arm, the raw URL within 500 characters of an evaluator reached through wp_remote_get, is uncovered and is the part worth porting",
	"php_eval_decode_chain":            "Rename, not a gap: php_eval_base64_chain is the same nested-decoder regex, verified on a gzuncompress arm the first sample did not use",
	"php_hex_string_obfuscation":       "Tier 2: silent on both samples; no realistic benign control establishes whether generated binary parsers can satisfy its concatenation shape. Validate against real code before porting",
	"php_open_basedir_bypass":          "Tier 2: silent on both samples, yet fires on a hosting support plugin's server diagnostics screen. Redesign before porting",
	"php_open_basedir_override":        "Rename, not a gap: the same open_basedir reset already ships as exploit_open_basedir_escape",
	"revshell_weevely_agent":           "Tier 1: silent on the corpus, on a 291k-file live sample, and on a benign control (a PHP 5 create_function shim). Ready to port",
	"spam_base64_links":                "Tier 2: already fires in realtime on live data, and fires on a theme echoing an inline base64 SVG logo. Redesign before porting",
	"spam_comment_injector":            "Tier 2: 15 port-induced live hits on WordPress core .js; also already a live realtime false positive on core comment handling",
	"spam_hidden_div_links":            "Tier 1: silent everywhere, and silent by construction: the {3,} anchor repetition cannot cross the closing tag of each link, so three consecutive links in ordinary markup never satisfy it. Repair the regex before porting",
	"spam_link_injector":               "Covered and HARDENED under another name: spam_wp_footer_injection requires the hide directive inside an inline style attribute, which is what keeps a plugin echoing a style block beside a visible link from matching. This .yml form has no such requirement",
	"spam_pharma_generic":              "Tier 1: spam_pharma covers the same three-signal proximity but its drug list omits pharmacy, pharmacie and ambien. Widen that list rather than ship a second rule",
	"spam_redirect_chain":              "Tier 2: silent on both samples, yet fires on a mobile and desktop redirect keyed on the user agent. Redesign before porting",
	"spam_seo_link_injection":          "Tier 2: silent on both samples; dofollow beside the generic word slot is ambiguous, but no realistic benign control reproduces it. Validate against real code before porting",
	"spam_sitemap_hijack":              "Tier 2: silent on both samples, yet fires on a sitemap listing a legitimate .xyz URL. Redesign before porting",
	"spam_wp_options_inject":           "Tier 2: silent on both samples, yet fires on an authenticated migration step updating a staged default-prefix options table. Redesign before porting",
	"spam_wp_post_injector":            "Tier 2: silent on both samples, yet fires on an authenticated gaming-review theme demo importer. Redesign before porting",
	"webshell_adminer_abuse":           "Policy finding: the rule identifies Adminer itself. Reporting an unexpected standalone database administration surface is intentional even for a stock copy. Ready to port as a high-risk dual-use tool detection",
	"webshell_generic_eval_request":    "Covered and HARDENED under another name: webshell_generic_passthru now accepts request data assigned to a local and evaluated later, which was the uncovered arm, and it still requires a PHP open tag that this .yml form does not",
	"webshell_generic_shell_exec":      "Tier 2: port-induced live hit on plugin .js",
	"webshell_hex_function_name":       "Tier 2: silent on both samples, yet fires on a MIME parser holding a hex-escaped CRLF separator and invoking a parser callback. Redesign before porting",
	"webshell_litespeed_backdoor":      "Rename, not a gap: identical regexes already ship as webshell_litespeed_disguise",
	"webshell_net2ftp_shell":           "Tier 2: co-occurrence of a brand string, exec( and $_POST with no adjacency required. Fires on a scanner plugin's own signature list. A real net2ftp shell reaches webshell_generic_passthru through its request-fed sink, so the brand adds only false positives",
	"webshell_phpfilemanager":          "Tier 2: min_match 1 over two brand strings with no regex, so any mention matches. Fires on a scanner plugin's own signature list, which is the family behind the 2026-07-21 flood. Redesign before porting",
	"webshell_tiny_file_manager":       "Policy finding: the rule identifies Tiny File Manager itself. Reporting an unexpected standalone file administration surface is intentional even for a stock copy. Ready to port as a high-risk dual-use tool detection",
	"webshell_wp_fake_theme":           "Covered and HARDENED under another name: webshell_wp_fake_plugin now opens on a theme header too, so a fake-theme shell reaches its request-fed and encoded-payload arms. This .yml form is bare co-occurrence of a theme header, system( and $_GET, which a theme running a fixed command satisfies",
	"wp_core_file_modify":              "Rename, not a gap: identical regexes already ship as exploit_wp_core_modification",
	"wp_db_credential_dump":            "Tier 2: already fires in realtime on live data, and fires on a backup plugin recording database coordinates in its manifest. Redesign before porting",
	"wp_fake_plugin_eval":              "Covered and HARDENED under another name: webshell_wp_fake_plugin requires the sink to consume request input or an encoded blob. This .yml form fires on any execution-sink call within six lines of a plugin header, regardless of its input",
	"wp_fake_plugin_upload":            "Covered and HARDENED under another name: dropper_uploader_no_auth bounds file size and suppresses authenticated, validated, and mail-only upload handlers. This .yml form is bare co-occurrence of a plugin header and move_uploaded_file, which ordinary upload plugins can satisfy, and it already fires in realtime on live data",
	"wp_login_bruteforce":              "Tier 2: 20 port-induced live hits on clean plugin .js bundles",
	"wp_plugin_backdoor_contact_form":  "Tier 2: port-induced hits on .pot translation catalogues",
	"wp_theme_editor_rce":              "Tier 2: uncovered, but the rule keys on wp_update_theme, which is not a WordPress function and matches core's wp_update_themes as a substring. Establish the intended signal before porting",
	"wp_user_enum":                     "Tier 2: silent on both samples, yet fires on a headless front end pulling the public author list. Redesign before porting",
	"wp_woocommerce_card_skimmer":      "Tier 2: unbounded gap between a card-field name and a network call; port-induced hits on .map files, and already a live realtime false positive at scale",
}

// renamedYARARules records the scheduled-scan rule that covers a differently
// named YAML rule. Keeping aliases machine-readable makes a deleted or renamed
// YARA counterpart fail instead of silently turning a rename into a real gap.
//
// An alias asserts coverage; it does not prove it. Shared literals are not
// shared behaviour, and a covering rule can fire on a sample only because that
// sample carried an unrelated signal. Each claim here was checked by scanning a
// true positive against the shipped rule set with the candidate absent, then
// re-checked against a variant built to remove the signal that produced the
// first hit.
// coveredByAnotherRule reports whether a backlog reason claims the detection
// already ships under a different name. Two shapes qualify: a plain rename, and
// a .yar twin that is strictly stronger than the .yml form. Both must name the
// covering rule in renamedYARARules so the claim is checked rather than trusted.
func coveredByAnotherRule(reason string) bool {
	return strings.HasPrefix(reason, "Rename") || strings.HasPrefix(reason, "Covered")
}

var renamedYARARules = map[string]string{
	"backdoor_cron_reverse_shell":   "backdoor_cron_downloader",
	"backdoor_wp_muplugin_loader":   "backdoor_wp_muplugin",
	"cgi_bash_webshell":             "cgi_webshell_bash",
	"dropper_php_stream_wrapper":    "dropper_stream_wrapper_abuse",
	"exploit_htaccess_handler":      "exploit_htaccess_handler_abuse",
	"exploit_wp_xmlrpc":             "exploit_wp_xmlrpc_abuse",
	"gsocket_persistence":           "gsocket_cron_persistence",
	"miner_coinhive_js":             "miner_coinhive",
	"miner_cryptoloot_js":           "miner_cryptoloot",
	"miner_shell_script":            "miner_shell_downloader",
	"network_brute_force":           "network_brute_force_tool",
	"obfuscation_assert_string":     "obfuscation_assert_exec",
	"php_dropper_gist":              "php_dropper_github_gist",
	"php_eval_decode_chain":         "php_eval_base64_chain",
	"php_open_basedir_override":     "exploit_open_basedir_escape",
	"spam_link_injector":            "spam_wp_footer_injection",
	"webshell_generic_eval_request": "webshell_generic_passthru",
	"webshell_litespeed_backdoor":   "webshell_litespeed_disguise",
	"webshell_wp_fake_theme":        "webshell_wp_fake_plugin",
	"wp_core_file_modify":           "exploit_wp_core_modification",
	"wp_fake_plugin_eval":           "webshell_wp_fake_plugin",
	"wp_fake_plugin_upload":         "dropper_uploader_no_auth",
}

// realtimeOnlyRuleBaseline freezes the initial burn-down membership. Keep
// ported names here after removing them from realtimeOnlyRules: this permanent
// baseline is what makes any new exception fail instead of letting the list
// grow to hide a parity regression.
const realtimeOnlyRuleBaseline = `
backdoor_cron_reverse_shell
backdoor_iconcache
backdoor_php_auto_append
backdoor_systemd_service
backdoor_wp_muplugin_loader
cgi_bash_webshell
cgi_haxor_extension
credential_logger
credential_mailer
dropper_php_stream_wrapper
dropper_wget_exec
dropper_wp_plugin_installer
exfil_wp_config_reader
exploit_cpanel_api_abuse
exploit_htaccess_handler
exploit_php_fpm_rce
exploit_wp_fake_plugin_installer
exploit_wp_options_inject
exploit_wp_rest_api
exploit_wp_xmlrpc
gsocket_persistence
mailer_bombermail
mailer_exim_exploit
mailer_phpmailer_abuse
miner_coinhive_js
miner_cryptoloot_js
miner_monero_wallet
miner_shell_script
network_brute_force
network_http_tunnel
obfuscation_assert_string
obfuscation_compact_unpack
obfuscation_create_function
obfuscation_ionCube_fake
phishing_dhl_fedex
phishing_google_drive
phishing_onedrive
phishing_webmail
phishing_workers_dev_exfil
php_dropper_gist
php_dropper_raw_github
php_eval_decode_chain
php_hex_string_obfuscation
php_open_basedir_bypass
php_open_basedir_override
revshell_weevely_agent
spam_base64_links
spam_chinese_seo
spam_comment_injector
spam_hidden_div_links
spam_japanese_seo
spam_link_injector
spam_pharma_generic
spam_redirect_chain
spam_seo_link_injection
spam_sitemap_hijack
spam_wp_options_inject
spam_wp_post_injector
webshell_adminer_abuse
webshell_generic_eval_request
webshell_generic_shell_exec
webshell_hex_function_name
webshell_litespeed_backdoor
webshell_net2ftp_shell
webshell_phpfilemanager
webshell_tiny_file_manager
webshell_wp_fake_theme
wp_core_file_modify
wp_cron_backdoor
wp_db_credential_dump
wp_fake_plugin_eval
wp_fake_plugin_upload
wp_login_bruteforce
wp_plugin_backdoor_contact_form
wp_theme_editor_rce
wp_user_enum
wp_woocommerce_card_skimmer
`

var yaraRuleDeclaration = regexp.MustCompile(`(?m)^[\t ]*(?:(?:private|global)[\t ]+)*rule[\t ]+([A-Za-z_][A-Za-z0-9_]*)\b`)

func TestEveryYAMLRuleHasYARACounterpart(t *testing.T) {
	configsDir := filepath.Join("..", "..", "configs")

	yamlData, err := os.ReadFile(filepath.Join(configsDir, "malware.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []struct {
			Name string `yaml:"name"`
		} `yaml:"rules"`
	}
	if unmarshalErr := yaml.Unmarshal(yamlData, &doc); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if len(doc.Rules) == 0 {
		t.Fatal("malware.yml parsed to zero rules")
	}
	yamlNames := make(map[string]bool, len(doc.Rules))
	var duplicateYAMLNames []string
	for _, rule := range doc.Rules {
		if yamlNames[rule.Name] {
			duplicateYAMLNames = append(duplicateYAMLNames, rule.Name)
		}
		yamlNames[rule.Name] = true
	}
	if len(duplicateYAMLNames) > 0 {
		sort.Strings(duplicateYAMLNames)
		t.Errorf("malware.yml contains duplicate rule names: %v", duplicateYAMLNames)
	}

	yaraData, err := os.ReadFile(filepath.Join(configsDir, "malware.yar"))
	if err != nil {
		t.Fatal(err)
	}
	yaraNames := make(map[string]bool)
	var duplicateYARANames []string
	for _, name := range extractYARARuleNames(yaraData) {
		if yaraNames[name] {
			duplicateYARANames = append(duplicateYARANames, name)
		}
		yaraNames[name] = true
	}
	if len(yaraNames) == 0 {
		t.Fatal("malware.yar parsed to zero rules")
	}
	if len(duplicateYARANames) > 0 {
		sort.Strings(duplicateYARANames)
		t.Errorf("malware.yar contains duplicate rule names: %v", duplicateYARANames)
	}

	baselineNames := make(map[string]bool)
	for _, name := range strings.Fields(realtimeOnlyRuleBaseline) {
		if baselineNames[name] {
			t.Fatalf("realtime-only baseline contains duplicate rule %q", name)
		}
		baselineNames[name] = true
	}

	var grownBacklog, invalidRenames, missingReasons, staleBacklog []string
	for name, reason := range realtimeOnlyRules {
		if !baselineNames[name] {
			grownBacklog = append(grownBacklog, name)
		}
		if strings.TrimSpace(reason) == "" {
			missingReasons = append(missingReasons, name)
		}
		if !yamlNames[name] || yaraNames[name] {
			staleBacklog = append(staleBacklog, name)
		}
		if coveredByAnotherRule(reason) && renamedYARARules[name] == "" {
			invalidRenames = append(invalidRenames, name+"->missing alias")
		}
	}
	for yamlName, yaraName := range renamedYARARules {
		reason := realtimeOnlyRules[yamlName]
		if yamlName == yaraName || !yamlNames[yamlName] || !yaraNames[yaraName] || !coveredByAnotherRule(reason) || !reasonMentionsRule(reason, yaraName) {
			invalidRenames = append(invalidRenames, yamlName+"->"+yaraName)
		}
	}

	var unported []string
	for name := range yamlNames {
		if !yaraNames[name] && realtimeOnlyRules[name] == "" {
			unported = append(unported, name)
		}
	}

	sort.Strings(grownBacklog)
	sort.Strings(invalidRenames)
	sort.Strings(missingReasons)
	sort.Strings(staleBacklog)
	sort.Strings(unported)
	if len(grownBacklog) > 0 {
		t.Errorf("realtimeOnlyRules is a burn-down list and may not grow; port these new exceptions instead: %v", grownBacklog)
	}
	if len(missingReasons) > 0 {
		t.Errorf("realtimeOnlyRules entries require a non-empty porting reason: %v", missingReasons)
	}
	if len(invalidRenames) > 0 {
		t.Errorf("renamed YAML rules must name a live, differently named YARA counterpart in their reason: %v", invalidRenames)
	}
	if len(unported) > 0 {
		t.Errorf("%d rules exist in malware.yml with no malware.yar counterpart, so on-demand and scheduled scans cannot fire them: %v", len(unported), unported)
	}
	if len(staleBacklog) > 0 {
		t.Errorf("realtimeOnlyRules contains %d stale entries no longer exclusive to malware.yml; delete them: %v", len(staleBacklog), staleBacklog)
	}
}

func reasonMentionsRule(reason, ruleName string) bool {
	for _, token := range strings.FieldsFunc(reason, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_'
	}) {
		if token == ruleName {
			return true
		}
	}
	return false
}

func TestReasonMentionsRule(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		ruleName string
		want     bool
	}{
		{name: "standalone target", reason: "Rename: scheduled_rule covers it", ruleName: "scheduled_rule", want: true},
		{name: "target before punctuation", reason: "Covered by scheduled_rule.", ruleName: "scheduled_rule", want: true},
		{name: "target prefix", reason: "Rename: scheduled_rule_extra covers it", ruleName: "scheduled_rule"},
		{name: "target suffix", reason: "Rename: old_scheduled_rule covers it", ruleName: "scheduled_rule"},
		{name: "missing target", reason: "Rename: another_rule covers it", ruleName: "scheduled_rule"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := reasonMentionsRule(tc.reason, tc.ruleName); got != tc.want {
				t.Errorf("reasonMentionsRule(%q, %q) = %t, want %t", tc.reason, tc.ruleName, got, tc.want)
			}
		})
	}
}

func TestExtractYARARuleNames(t *testing.T) {
	source := []byte(`
/*
rule block_comment { condition: true }
*/
// rule line_comment { condition: true }
rule plain { condition: true }
    private rule indented_private { condition: true }
global rule global_rule { condition: true }
private global rule both_modifiers {
    strings:
        $quoted = "rule quoted_string { condition: true }"
        $regex = /rule regex_literal \/\* not_a_comment \*\//
    condition:
        true
}
`)
	want := []string{"plain", "indented_private", "global_rule", "both_modifiers"}
	if got := extractYARARuleNames(source); !slices.Equal(got, want) {
		t.Fatalf("rule names = %v, want %v", got, want)
	}
}

func extractYARARuleNames(source []byte) []string {
	code := maskYARACommentsAndLiterals(source)
	matches := yaraRuleDeclaration.FindAllSubmatch(code, -1)
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		names = append(names, string(match[1]))
	}
	return names
}

func maskYARACommentsAndLiterals(source []byte) []byte {
	const (
		codeState = iota
		lineCommentState
		blockCommentState
		stringState
		regexState
	)

	masked := append([]byte(nil), source...)
	state := codeState
	escaped := false
	var previousSignificant byte
	for i := 0; i < len(source); i++ {
		ch := source[i]
		switch state {
		case codeState:
			switch {
			case ch == '/' && i+1 < len(source) && source[i+1] == '/':
				masked[i], masked[i+1] = ' ', ' '
				i++
				state = lineCommentState
			case ch == '/' && i+1 < len(source) && source[i+1] == '*':
				masked[i], masked[i+1] = ' ', ' '
				i++
				state = blockCommentState
			case ch == '"':
				masked[i] = ' '
				escaped = false
				state = stringState
			case ch == '/' && previousSignificant == '=':
				masked[i] = ' '
				escaped = false
				state = regexState
			case ch == '\n':
				previousSignificant = 0
			case ch != ' ' && ch != '\t' && ch != '\r':
				previousSignificant = ch
			}

		case lineCommentState:
			if ch == '\n' {
				state = codeState
				previousSignificant = 0
			} else {
				masked[i] = ' '
			}

		case blockCommentState:
			switch {
			case ch == '*' && i+1 < len(source) && source[i+1] == '/':
				masked[i], masked[i+1] = ' ', ' '
				i++
				state = codeState
			case ch != '\n':
				masked[i] = ' '
			default:
				previousSignificant = 0
			}

		case stringState:
			if ch != '\n' {
				masked[i] = ' '
			}
			switch {
			case escaped:
				escaped = false
			case ch == '\\':
				escaped = true
			case ch == '"':
				state = codeState
				previousSignificant = '"'
			}

		case regexState:
			if ch != '\n' {
				masked[i] = ' '
			}
			switch {
			case escaped:
				escaped = false
			case ch == '\\':
				escaped = true
			case ch == '/':
				state = codeState
				previousSignificant = '/'
			}
		}
	}
	return masked
}
