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
// fanotify and finding re-check alone. An entry here is therefore a rule that
// can only ever fire while the daemon watches the write -- invisible to
// `csm scan`, and to every file already sitting on disk.
//
// This map may only shrink.
var realtimeOnlyRules = map[string]string{
	"backdoor_cron_reverse_shell":      "Rename, not a gap: byte-identical regex already ships as backdoor_cron_downloader, so the detection runs on every scan. Porting it would double-report",
	"backdoor_php_auto_append":         "Tier 2: htaccess-scoped; the directive also appears as a string literal in security-plugin PHP, giving 7 port-induced live hits",
	"backdoor_systemd_service":         "Tier 2: min_match 1 with a single generic literal (the ExecStart directive) and require_regex false, so the regex is decorative and ANY systemd unit satisfies the rule. Caught by a benign-unit control sample, not by corpus measurement",
	"cgi_bash_webshell":                "Rename, and the .yar side is the HARDENED one: cgi_webshell_bash requires the bash shebang at offset 0, which is what keeps the four bare substrings from matching any large bundle. Porting this .yml version by name would replace a hardened rule with the weak original",
	"cgi_haxor_extension":              "Tier 2: content signal is the literal shebang, which occurs by chance in binary; 473 live hits across 22 file types including .jpg, .pdf, .zip and fonts. Real detection is the .haxor filename and belongs in internal/checks",
	"credential_logger":                "Tier 1: port adds no new hits, but the rule is already a live realtime false positive on security-plugin login code; worth fixing separately",
	"credential_mailer":                "Tier 1: port adds no new hits, but the rule is already a live realtime false positive on WooCommerce and Elementor registration mail; worth fixing separately",
	"dropper_php_stream_wrapper":       "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"dropper_wp_plugin_installer":      "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"exfil_wp_config_reader":           "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"exploit_cpanel_api_abuse":         "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"exploit_htaccess_handler":         "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"exploit_php_fpm_rce":              "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"exploit_wp_fake_plugin_installer": "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"exploit_wp_options_inject":        "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"exploit_wp_rest_api":              "Tier 2: 29 port-induced live hits, every one on a .mo translation catalogue",
	"exploit_wp_xmlrpc":                "Rename, not a gap: identical regexes already ship as exploit_wp_xmlrpc_abuse",
	"mailer_bombermail":                "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"mailer_exim_exploit":              "Tier 2: 268 port-induced live hits, almost all on plugin .js assets; also already a live realtime false positive on the PHPMailer SMTP class in WordPress core",
	"mailer_phpmailer_abuse":           "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"miner_coinhive_js":                "Rename, not a gap: identical regexes already ship as miner_coinhive",
	"miner_cryptoloot_js":              "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"miner_monero_wallet":              "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"miner_shell_script":               "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"network_brute_force":              "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"network_http_tunnel":              "Tier 2: port-induced hit on plugin .js; also already a live realtime false positive on the FTP sockets class in WordPress core",
	"obfuscation_create_function":      "Tier 2: 4 port-induced live hits on plugin readme .txt; also already a live realtime false positive",
	"obfuscation_ionCube_fake":         "Tier 2: min_match 2 with two ionCube brand literals, so a legitimate loader stub fires it without the regex ever matching. Commercial encoded PHP is absent from the corpus, so measurement alone missed this",
	"phishing_dhl_fedex":               "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"phishing_google_drive":            "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"phishing_onedrive":                "Tier 1: port adds no new hits, but the rule already fires in realtime on live data; worth fixing separately",
	"phishing_webmail":                 "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"phishing_workers_dev_exfil":       "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"php_dropper_gist":                 "Rename, not a gap: identical literals already ship as php_dropper_github_gist",
	"php_dropper_raw_github":           "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"php_eval_decode_chain":            "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"php_hex_string_obfuscation":       "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"php_open_basedir_bypass":          "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"revshell_weevely_agent":           "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"spam_base64_links":                "Tier 1: port adds no new hits, but the rule already fires in realtime on live data; worth fixing separately",
	"spam_comment_injector":            "Tier 2: 15 port-induced live hits on WordPress core .js; also already a live realtime false positive on core comment handling",
	"spam_hidden_div_links":            "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"spam_link_injector":               "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"spam_pharma_generic":              "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"spam_redirect_chain":              "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"spam_seo_link_injection":          "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"spam_sitemap_hijack":              "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"spam_wp_options_inject":           "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"spam_wp_post_injector":            "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"webshell_adminer_abuse":           "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"webshell_generic_eval_request":    "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"webshell_generic_shell_exec":      "Tier 2: port-induced live hit on plugin .js",
	"webshell_hex_function_name":       "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"webshell_litespeed_backdoor":      "Rename, not a gap: identical regexes already ship as webshell_litespeed_disguise",
	"webshell_net2ftp_shell":           "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"webshell_phpfilemanager":          "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"webshell_tiny_file_manager":       "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"webshell_wp_fake_theme":           "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"wp_core_file_modify":              "Rename, not a gap: identical regexes already ship as exploit_wp_core_modification",
	"wp_db_credential_dump":            "Tier 1: port adds no new hits, but the rule already fires in realtime on live data; worth fixing separately",
	"wp_fake_plugin_eval":              "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"wp_fake_plugin_upload":            "Tier 1: port adds no new hits, but the rule already fires in realtime on live data; worth fixing separately",
	"wp_login_bruteforce":              "Tier 2: 20 port-induced live hits on clean plugin .js bundles",
	"wp_plugin_backdoor_contact_form":  "Tier 2: port-induced hits on .pot translation catalogues",
	"wp_theme_editor_rce":              "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"wp_user_enum":                     "Tier 1: silent on the clean corpus and on a 291k-file live sample; ready to port",
	"wp_woocommerce_card_skimmer":      "Tier 2: unbounded gap between a card-field name and a network call; port-induced hits on .map files, and already a live realtime false positive at scale",
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

	var grownBacklog, missingReasons, staleBacklog []string
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
	}

	var unported []string
	for name := range yamlNames {
		if !yaraNames[name] && realtimeOnlyRules[name] == "" {
			unported = append(unported, name)
		}
	}

	sort.Strings(grownBacklog)
	sort.Strings(missingReasons)
	sort.Strings(staleBacklog)
	sort.Strings(unported)
	if len(grownBacklog) > 0 {
		t.Errorf("realtimeOnlyRules is a burn-down list and may not grow; port these new exceptions instead: %v", grownBacklog)
	}
	if len(missingReasons) > 0 {
		t.Errorf("realtimeOnlyRules entries require a non-empty porting reason: %v", missingReasons)
	}
	if len(unported) > 0 {
		t.Errorf("%d rules exist in malware.yml with no malware.yar counterpart, so on-demand and scheduled scans cannot fire them: %v", len(unported), unported)
	}
	if len(staleBacklog) > 0 {
		t.Errorf("realtimeOnlyRules contains %d stale entries no longer exclusive to malware.yml; delete them: %v", len(staleBacklog), staleBacklog)
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
