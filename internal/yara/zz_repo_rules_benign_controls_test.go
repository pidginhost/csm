//go:build yara

package yara_test

import (
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/pidginhost/csm/internal/signatures"
	csmyara "github.com/pidginhost/csm/internal/yara"
)

// knownRealtimeFalsePositives records realtime-only rules that fire on code a
// hosting customer would legitimately run, together with what the control is.
// It is a burn-down list: repairing a rule makes its entry stale, and a stale
// entry must be deleted rather than left to describe a fault that is gone.
//
// Every rule listed here is measured silent on 15,992 files of clean WordPress
// core and popular plugins AND on a 291k-file live sample. Measurement finds
// what the sample contains; these controls are how the shapes it does not
// contain get found. A rule measured silent is therefore not yet safe to port.
var knownRealtimeFalsePositives = map[string]string{
	"credential_logger":                "a newsletter opt-in handler writing a sanitized posted address to a log file",
	"exfil_wp_config_reader":           "a migration plugin copying wp-config into its export manifest",
	"exploit_cpanel_api_abuse":         "a vendor SDK helper building a cPanel session URL",
	"exploit_wp_fake_plugin_installer": "a plugin writing its own compiled template cache from a packed blob",
	"exploit_wp_options_inject":        "a site-address settings screen guarded by a capability check and a nonce",
	"mailer_bombermail":                "an outbound throttling plugin listing abuse terms beside an ordinary digest loop",
	"miner_monero_wallet":              "a project support page showing a donation address",
	"network_brute_force":              "a stored-password option read beside an unrelated connection helper",
	"phishing_dhl_fedex":               "a shipping plugin carrier settings screen posting an API key to the carrier own domain",
	"phishing_google_drive":            "a Drive backup plugin settings screen taking a service-account key",
	"phishing_webmail":                 "a stock Roundcube login page, which ships on every cPanel host",
	"phishing_workers_dev_exfil":       "a site whose own API is hosted on Cloudflare Workers",
	"php_hex_string_obfuscation":       "a byte-order-mark table in a CSV import library",
	"php_open_basedir_bypass":          "a hosting support plugin server diagnostics screen",
	"spam_base64_links":                "a theme echoing an inline base64 SVG logo",
	"spam_redirect_chain":              "a mobile and desktop redirect keyed on the user agent",
	"spam_seo_link_injection":          "documentation linking to a slot machine API",
	"spam_sitemap_hijack":              "a sitemap listing a legitimate .xyz URL",
	"spam_wp_options_inject":           "a migration plugin search-replace query against the options table",
	"spam_wp_post_injector":            "a gaming-review theme importing its demo content",
	"webshell_adminer_abuse":           "the Adminer header comment, which is to say Adminer itself",
	"webshell_hex_function_name":       "a MIME parser holding a hex-escaped CRLF separator and calling a parser callback",
	"webshell_net2ftp_shell":           "a scanner plugin own signature list",
	"webshell_phpfilemanager":          "a scanner plugin own signature list",
	"webshell_tiny_file_manager":       "a stock Tiny File Manager install",
	"wp_db_credential_dump":            "a backup plugin recording database coordinates in its manifest",
	"wp_user_enum":                     "a headless front end pulling the public author list",
}

// benignControls are files a legitimate plugin, theme or hosting tool would
// ship. No rule in malware.yar may match any of them, and the only malware.yml
// rules permitted to match are the ones knownRealtimeFalsePositives admits to.
var benignControls = []struct {
	name     string
	ext      string
	knownHit string
	sample   string
}{
	{
		name:     "credential_logger",
		ext:      ".php",
		knownHit: "credential_logger",
		sample: `<?php
// Newsletter opt-in logger shipped by a legitimate plugin.
$f = fopen(WP_CONTENT_DIR . '/uploads/optin.log', 'a');
fwrite($f, sanitize_email($_POST['email']) . "\n");
fclose($f);
`,
	},
	{
		name: "dropper_wp_plugin_installer",
		ext:  ".php",
		sample: `<?php
// A legitimate plugin writing its own compiled template cache.
$target = WP_CONTENT_DIR . '/plugins/my-builder/cache/compiled-header.php';
file_put_contents($target, $compiled);
`,
	},
	{
		name:     "exfil_wp_config_reader",
		ext:      ".php",
		knownHit: "exfil_wp_config_reader",
		sample: `<?php
// Migration plugin capturing config for the export manifest.
$cfg = file_get_contents(ABSPATH . 'wp-config.php'); file_put_contents($manifest, $cfg);
`,
	},
	{
		name:     "exploit_cpanel_api_abuse",
		ext:      ".php",
		knownHit: "exploit_cpanel_api_abuse",
		sample: `<?php
// Hosting control panel helper documented in the vendor SDK.
$base = 'https://' . $host . ':2083/cpsess' . $token . '/execute/Email/list_pops';
$r = wp_remote_get($base);
`,
	},
	{
		name: "exploit_php_fpm_rce",
		ext:  ".py",
		sample: `# nginx fastcgi param builder in a deployment tool
params = {"PATH_INFO": path, "PHP_VALUE": "auto_prepend_file=/srv/app/prepend.php"}
render(params)
`,
	},
	{
		name:     "exploit_wp_fake_plugin_installer",
		ext:      ".php",
		knownHit: "exploit_wp_fake_plugin_installer",
		sample: `<?php
register_activation_hook(__FILE__, 'seed_templates');
function seed_templates() {
    file_put_contents(plugin_dir_path(__FILE__) . 'cache/tpl.php', gzinflate($packed_template));
}
`,
	},
	{
		name:     "exploit_wp_options_inject",
		ext:      ".php",
		knownHit: "exploit_wp_options_inject",
		sample: `<?php
// Site-address settings screen in a multisite management plugin.
if (current_user_can('manage_options') && check_admin_referer('site_addr')) {
    update_option('siteurl', $_POST['siteurl']);
}
`,
	},
	{
		name:     "mailer_bombermail",
		ext:      ".php",
		knownHit: "mailer_bombermail",
		sample: `<?php
// Abuse-pattern list in an outbound mail throttling plugin.
$abuse_terms = array('mail_bomb', 'email_bomb', 'bomber');
for ($i = 0; $i < $count; $i++) { mail($queue[$i]['to'], $queue[$i]['subject'], $queue[$i]['body']); }
`,
	},
	{
		name: "mailer_phpmailer_abuse",
		ext:  ".php",
		sample: `<?php
$m = new PHPMailer(true);
$m->addAddress(sanitize_email(get_option('admin_email')));
mail($fallback, 'notice', 'body');
`,
	},
	{
		name:     "miner_monero_wallet",
		ext:      ".html",
		knownHit: "miner_monero_wallet",
		sample: `<h3>Support the project</h3>
<p>We run a community pool; our miner is open source. Monero donations:</p>
<code>4A999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999</code>
`,
	},
	{
		name:     "network_brute_force",
		ext:      ".php",
		knownHit: "network_brute_force",
		sample: `<?php
$passwords = get_option('stored_ftp_passwords');
function probe($host) { return fsockopen($host, 21, $errno, $errstr, 5); }
`,
	},
	{
		name:     "phishing_dhl_fedex",
		ext:      ".php",
		knownHit: "phishing_dhl_fedex",
		sample: `<?php
// Settings screen of a WooCommerce shipping plugin.
?>
<h2>Carrier accounts</h2>
<p>Enable delivery notification emails and print the tracking number on the packing slip.</p>
<form method="post" action="https://ws.fedex.com/web-services"><input type="password" name="carrier_api_key"></form>
`,
	},
	{
		name:     "phishing_google_drive",
		ext:      ".php",
		knownHit: "phishing_google_drive",
		sample: `<?php
// Settings screen of a Google Drive backup plugin.
?>
<h2>Google Drive backup</h2>
<p>Authorise this site at <a href="https://accounts.google.com/o/oauth2/v2/auth">accounts.google.com</a>, then paste the service account key below.</p>
<form method="post" action="options.php">
  <input type="password" name="drive_service_key" autocomplete="off">
</form>
`,
	},
	{
		name:     "phishing_webmail",
		ext:      ".html",
		knownHit: "phishing_webmail",
		sample: `<title>Roundcube Webmail Login</title>
<form action="/roundcube/index.php" method="post"><input type="password" name="_pass"></form>
`,
	},
	{
		name:     "phishing_workers_dev_exfil",
		ext:      ".html",
		knownHit: "phishing_workers_dev_exfil",
		sample: `<script>
// Legitimate site hosting its API on Cloudflare Workers.
fetch('https://api.example.workers.dev/v1/products').then(function (r) { return r.json(); });
</script>
`,
	},
	{
		name:     "php_hex_string_obfuscation",
		ext:      ".php",
		knownHit: "php_hex_string_obfuscation",
		sample: `<?php
// Byte-order-mark table in a CSV import library.
$bom = "\xef" . "\xbb" . "\xbf" . "\xfe" . "\xff" . "\x00";
call_user_func($handler, $bom);
`,
	},
	{
		name:     "php_open_basedir_bypass",
		ext:      ".php",
		knownHit: "php_open_basedir_bypass",
		sample: `<?php
// Server diagnostics screen in a hosting support plugin.
echo ini_get('open_basedir');
chdir(ABSPATH);
$logs = glob(WP_CONTENT_DIR . '/debug*.log');
`,
	},
	{
		name: "revshell_weevely_agent",
		ext:  ".php",
		sample: `<?php
// Legacy PHP 5 callback shim.
$maker = create_function;
$fn=$maker('','return 1;');$fn();
`,
	},
	{
		name:     "spam_base64_links",
		ext:      ".php",
		knownHit: "spam_base64_links",
		sample: `<?php
// Inline SVG logo emitted by a theme.
echo base64_decode('PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMCAxMCI+PC9zdmc+');
`,
	},
	{
		name: "spam_hidden_div_links",
		ext:  ".html",
		sample: `<div style="display: none"><a href="/a">A</a><a href="/b">B</a><a href="/c">C</a></div>
`,
	},
	{
		name:     "spam_redirect_chain",
		ext:      ".php",
		knownHit: "spam_redirect_chain",
		sample: `<?php
if (wp_is_mobile() && strpos($_SERVER['HTTP_USER_AGENT'], 'Android') !== false) { header("Location: /m/"); } else { header("Location: /desktop/"); }
`,
	},
	{
		name:     "spam_seo_link_injection",
		ext:      ".html",
		knownHit: "spam_seo_link_injection",
		sample: `<p>Our <a href="https://docs.example.test/slots" rel="dofollow">slot machine API</a> documentation.</p>
`,
	},
	{
		name:     "spam_sitemap_hijack",
		ext:      ".xml",
		knownHit: "spam_sitemap_hijack",
		sample: `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://blog.example.xyz/post</loc></url></urlset>
`,
	},
	{
		name:     "spam_wp_options_inject",
		ext:      ".php",
		knownHit: "spam_wp_options_inject",
		sample: `<?php
// Search-replace step of a legitimate migration plugin.
$wpdb->query("UPDATE {$wpdb->prefix}wp_options SET option_value = '{$new}' WHERE option_name = 'siteurl'");
`,
	},
	{
		name:     "spam_wp_post_injector",
		ext:      ".php",
		knownHit: "spam_wp_post_injector",
		sample: `<?php
// Demo content importer for a gaming-review theme.
wp_insert_post(array('post_title' => 'Top casino games reviewed', 'post_status' => 'draft'));
`,
	},
	{
		name:     "webshell_adminer_abuse",
		ext:      ".php",
		knownHit: "webshell_adminer_abuse",
		sample: `<?php
/** Adminer 4.8.1 - Database management in a single PHP file. https://www.adminer.org */
`,
	},
	{
		name:     "webshell_hex_function_name",
		ext:      ".php",
		knownHit: "webshell_hex_function_name",
		sample: `<?php
$sep = "\x0d\x0a\x0d\x0a"; $parser($sep);
`,
	},
	{
		name:     "webshell_net2ftp_shell",
		ext:      ".php",
		knownHit: "webshell_net2ftp_shell",
		sample: `<?php
// Signature list shipped by a malware scanner plugin.
$known_tools = array('net2ftp', 'adminer', 'phpminiadmin');
$callbacks = array('exec(', 'system(', 'passthru(');
$sources = array('$_POST', '$_GET');
`,
	},
	{
		name:     "webshell_phpfilemanager",
		ext:      ".php",
		knownHit: "webshell_phpfilemanager",
		sample: `<?php
// Signature list shipped by a malware scanner plugin.
$known_shells = array('c99', 'r57', 'phpFileManager', 'wso', 'b374k');
foreach ($known_shells as $needle) { $hits[$needle] = 0; }
`,
	},
	{
		name:     "webshell_tiny_file_manager",
		ext:      ".php",
		knownHit: "webshell_tiny_file_manager",
		sample: `<?php
// Tiny File Manager 2.5.3 - https://tinyfilemanager.github.io
$auth_users = array('admin' => password_hash('changeme', PASSWORD_DEFAULT));
`,
	},
	{
		name:     "wp_db_credential_dump",
		ext:      ".php",
		knownHit: "wp_db_credential_dump",
		sample: `<?php
// Backup plugin reading the config to record DB coordinates in its manifest.
$cfg = file_get_contents(ABSPATH . 'wp-config.php');
$keys = array('DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST');
`,
	},
	{
		name:     "wp_user_enum",
		ext:      ".php",
		knownHit: "wp_user_enum",
		sample: `<?php
// Headless front end pulling the public author list.
$u = wp_remote_get(home_url('/wp-json/wp/v2/users'));
`,
	},
}

// TestRealtimeRulesAgainstBenignControls is the counterpart to the clean-corpus
// gate. The corpus proves a rule is quiet on 15,992 real files; these controls
// prove it is quiet on the shapes the corpus happens not to contain, which is
// where every false positive recorded above was actually found.
func TestRealtimeRulesAgainstBenignControls(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	configsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs")

	yaraScanner, err := csmyara.NewScanner(configsDir)
	if err != nil {
		t.Fatalf("loading YARA rules: %v", err)
	}
	yamlScanner := signatures.NewScanner(configsDir)
	if err := yamlScanner.LoadError(); err != nil {
		t.Fatalf("loading YAML rules: %v", err)
	}

	exercised := make(map[string]bool)
	var undeclared []string
	for _, control := range benignControls {
		if control.knownHit != "" {
			exercised[control.knownHit] = true
			// The control names the rule it reproduces and the map explains why
			// the code is legitimate. Bind them, or deleting one leaves the
			// other describing a fault nothing checks.
			if _, declared := knownRealtimeFalsePositives[control.knownHit]; !declared {
				undeclared = append(undeclared, control.name+" -> "+control.knownHit)
			}
		}
		t.Run(control.name, func(t *testing.T) {
			knownFired := false
			var unexpected []string
			for _, match := range yamlScanner.ScanContent([]byte(control.sample), control.ext) {
				if match.RuleName == control.knownHit {
					knownFired = true
					continue
				}
				unexpected = append(unexpected, match.RuleName)
			}
			sort.Strings(unexpected)
			if len(unexpected) > 0 {
				t.Errorf("real-time rules matched legitimate code: %v", unexpected)
			}
			if control.knownHit != "" && !knownFired {
				t.Errorf("%s no longer matches this control; delete its knownRealtimeFalsePositives entry", control.knownHit)
			}

			var scheduled []string
			for _, match := range yaraScanner.ScanBytes([]byte(control.sample)) {
				scheduled = append(scheduled, match.RuleName)
			}
			sort.Strings(scheduled)
			if len(scheduled) > 0 {
				t.Errorf("scheduled-scan rules matched legitimate code: %v", scheduled)
			}
		})
	}

	sort.Strings(undeclared)
	if len(undeclared) > 0 {
		t.Errorf("controls name a rule with no knownRealtimeFalsePositives entry: %v", undeclared)
	}

	var unexercised []string
	for rule := range knownRealtimeFalsePositives {
		if !exercised[rule] {
			unexercised = append(unexercised, rule)
		}
	}
	sort.Strings(unexercised)
	if len(unexercised) > 0 {
		t.Errorf("admitted false positives need a control that reproduces them: %v", unexercised)
	}
}
