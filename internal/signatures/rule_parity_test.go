package signatures

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	"backdoor_cron_reverse_shell":      "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"backdoor_iconcache":               "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"backdoor_php_auto_append":         "Tier 2: htaccess-scoped; the directive also appears as a string literal in Wordfence PHP",
	"backdoor_systemd_service":         "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"backdoor_wp_muplugin_loader":      "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"cgi_bash_webshell":                "Tier 2: base64+eval+Content-type at min_match 3 matches WordPress core, Wordfence and minified JS once extension scoping is gone",
	"cgi_haxor_extension":              "Tier 2: the entire content signal is the literal shebang; the real detection is the .haxor filename and belongs in internal/checks",
	"credential_logger":                "Tier 2: matches Wordfence login-security code; already a live realtime false positive",
	"credential_mailer":                "Tier 2: matches legitimate WooCommerce and Elementor registration mail; already a live realtime false positive",
	"dropper_php_stream_wrapper":       "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"dropper_wget_exec":                "Tier 3: YARA-X rejects mixing greedy and non-greedy quantifiers; port drafted and differentially verified",
	"dropper_wp_plugin_installer":      "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"exfil_wp_config_reader":           "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"exploit_cpanel_api_abuse":         "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"exploit_htaccess_handler":         "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"exploit_php_fpm_rce":              "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"exploit_wp_fake_plugin_installer": "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"exploit_wp_options_inject":        "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"exploit_wp_rest_api":              "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"exploit_wp_xmlrpc":                "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"gsocket_persistence":              "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"mailer_bombermail":                "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"mailer_exim_exploit":              "Tier 2: matches the PHPMailer SMTP class shipped in WordPress core; already a live realtime false positive",
	"mailer_phpmailer_abuse":           "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"miner_coinhive_js":                "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"miner_cryptoloot_js":              "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"miner_monero_wallet":              "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"miner_shell_script":               "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"network_brute_force":              "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"network_http_tunnel":              "Tier 2: matches the FTP sockets class shipped in WordPress core; already a live realtime false positive",
	"obfuscation_assert_string":        "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"obfuscation_compact_unpack":       "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"obfuscation_create_function":      "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"obfuscation_ionCube_fake":         "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"phishing_dhl_fedex":               "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"phishing_google_drive":            "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"phishing_onedrive":                "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"phishing_webmail":                 "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"phishing_workers_dev_exfil":       "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"php_dropper_gist":                 "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"php_dropper_raw_github":           "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"php_eval_decode_chain":            "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"php_hex_string_obfuscation":       "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"php_open_basedir_bypass":          "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"php_open_basedir_override":        "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"revshell_weevely_agent":           "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"spam_base64_links":                "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"spam_chinese_seo":                 "Tier 3: YARA-X regexes match bytes, so the CJK codepoint class needs UTF-8 byte ranges; port drafted and differentially verified",
	"spam_comment_injector":            "Tier 2: matches WordPress core comment handling",
	"spam_hidden_div_links":            "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"spam_japanese_seo":                "Tier 3: YARA-X regexes match bytes, so the kana/CJK codepoint classes need UTF-8 byte ranges; port drafted and differentially verified",
	"spam_link_injector":               "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"spam_pharma_generic":              "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"spam_redirect_chain":              "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"spam_seo_link_injection":          "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"spam_sitemap_hijack":              "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"spam_wp_options_inject":           "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"spam_wp_post_injector":            "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"webshell_adminer_abuse":           "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"webshell_generic_eval_request":    "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"webshell_generic_shell_exec":      "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"webshell_hex_function_name":       "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"webshell_litespeed_backdoor":      "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"webshell_net2ftp_shell":           "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"webshell_phpfilemanager":          "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"webshell_tiny_file_manager":       "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"webshell_wp_fake_theme":           "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"wp_core_file_modify":              "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"wp_cron_backdoor":                 "Tier 3: YARA-X rejects mixing greedy and non-greedy quantifiers; port drafted and differentially verified",
	"wp_db_credential_dump":            "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"wp_fake_plugin_eval":              "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"wp_fake_plugin_upload":            "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"wp_login_bruteforce":              "Tier 2: matches clean WooCommerce client bundles once extension scoping is gone",
	"wp_plugin_backdoor_contact_form":  "Tier 2: matches a Wordfence translation catalogue",
	"wp_theme_editor_rce":              "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"wp_user_enum":                     "Tier 1: silent on the clean corpus; port pending live-sample validation",
	"wp_woocommerce_card_skimmer":      "Tier 2: unbounded gap between a card-field name and a network call matches clean minified bundles; already a live realtime false positive",
}

func TestEveryYAMLRuleHasYARACounterpart(t *testing.T) {
	configsDir := filepath.Join("..", "..", "configs")

	yamlData, err := os.ReadFile(filepath.Join(configsDir, "malware.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []struct {
			Name     string `yaml:"name"`
			Severity string `yaml:"severity"`
		} `yaml:"rules"`
	}
	if unmarshalErr := yaml.Unmarshal(yamlData, &doc); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if len(doc.Rules) == 0 {
		t.Fatal("malware.yml parsed to zero rules")
	}

	yaraData, err := os.ReadFile(filepath.Join(configsDir, "malware.yar"))
	if err != nil {
		t.Fatal(err)
	}
	yaraNames := make(map[string]bool)
	for _, m := range regexp.MustCompile(`(?m)^rule\s+(\w+)`).FindAllStringSubmatch(string(yaraData), -1) {
		yaraNames[m[1]] = true
	}
	if len(yaraNames) == 0 {
		t.Fatal("malware.yar parsed to zero rules")
	}

	var unported, staleAllowlist []string
	for _, r := range doc.Rules {
		_, listed := realtimeOnlyRules[r.Name]
		if yaraNames[r.Name] {
			if listed {
				staleAllowlist = append(staleAllowlist, r.Name)
			}
			continue
		}
		if !listed {
			unported = append(unported, r.Name)
		}
	}

	sort.Strings(unported)
	sort.Strings(staleAllowlist)
	if len(unported) > 0 {
		t.Errorf("%d rules exist in malware.yml with no malware.yar counterpart, so on-demand and scheduled scans cannot fire them: %v", len(unported), unported)
	}
	if len(staleAllowlist) > 0 {
		t.Errorf("realtimeOnlyRules names %d rules that are now in malware.yar; delete these entries: %v", len(staleAllowlist), staleAllowlist)
	}
}
