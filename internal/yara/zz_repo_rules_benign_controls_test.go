//go:build yara

package yara_test

import (
	"path/filepath"
	"runtime"
	"sort"
	"strings"
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
	"credential_logger":          "a newsletter opt-in handler writing a sanitized posted address to a log file",
	"exfil_wp_config_reader":     "a migration plugin staging wp-config for an authenticated export",
	"exploit_cpanel_api_abuse":   "a vendor SDK helper building a cPanel session URL",
	"exploit_wp_options_inject":  "a site-address settings screen guarded by a capability check and a nonce",
	"mailer_bombermail":          "a malware scanner's mail-bomb signature catalogue",
	"miner_monero_wallet":        "a project support page showing a donation address",
	"network_brute_force":        "an FTP plugin checking the health of its stored account connections",
	"phishing_dhl_fedex":         "a shipping plugin settings screen describing tracking numbers and delivery notifications",
	"phishing_google_drive":      "a Drive backup plugin settings screen taking a service-account key",
	"phishing_workers_dev_exfil": "a site whose own API is hosted on Cloudflare Workers",
	"php_open_basedir_bypass":    "a hosting support plugin server diagnostics screen",
	"spam_base64_links":          "a theme echoing an inline base64 SVG logo",
	"spam_redirect_chain":        "a mobile and desktop redirect keyed on the user agent",
	"spam_sitemap_hijack":        "a sitemap listing a legitimate .xyz URL",
	"spam_wp_options_inject":     "an authenticated migration step updating a staged default-prefix options table",
	"spam_wp_post_injector":      "an authenticated gaming-review theme demo importer",
	"webshell_hex_function_name": "a MIME parser holding a hex-escaped CRLF separator and invoking a parser callback",
	"webshell_net2ftp_shell":     "a scanner plugin's own signature list",
	"webshell_phpfilemanager":    "a scanner plugin's own signature list",
	"wp_db_credential_dump":      "a backup plugin recording database coordinates in its manifest",
	"wp_user_enum":               "a headless front end pulling the public author list",
}

// benignControls are files a legitimate plugin, theme or hosting tool would
// ship. No active scheduled-scan rule may match any of them, and the only
// malware.yml rules permitted to match are the ones admitted above.
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
// Authenticated migration job staging the site configuration for its package.
if (!current_user_can('export') || !check_admin_referer('site_export')) { return; }
$cfg = file_get_contents(ABSPATH . 'wp-config.php'); file_put_contents($staging . '/wp-config.php', $cfg, LOCK_EX);
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
// Detection names in a malware scanner plugin's signature catalogue.
$signature_names = array('mail_bomb', 'email_bomb', 'bomber');
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
function saved_ftp_passwords() {
    $passwords = get_option('stored_ftp_passwords');
    return $passwords;
}
function open_ftp_connection($host) { return fsockopen($host, 21, $errno, $errstr, 5); }
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
<p>Enable delivery notification emails and print the tracking number on each packing slip.</p>
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
// Legacy PHP 5 callback factory retained by a compatibility library.
$factory = 'create_function';
$callback = $factory('', 'return 1;');
$callback();
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
		sample: `<nav class="mobile-menu"><div style="display: none"><a href="/about">About</a><a href="/support">Support</a><a href="/contact">Contact</a></div></nav>
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
// Authenticated migration step operating on a staged default-prefix table.
if (current_user_can('import') && check_admin_referer('site_import')) {
    $wpdb->query($wpdb->prepare("UPDATE wp_options SET option_value = %s WHERE option_name = 'siteurl'", esc_url_raw(wp_unslash($_POST['siteurl']))));
}
`,
	},
	{
		name:     "spam_wp_post_injector",
		ext:      ".php",
		knownHit: "spam_wp_post_injector",
		sample: `<?php
// Admin-only demo content importer for a gaming-review theme.
if (current_user_can('import') && check_admin_referer('theme_demo_import')) {
    wp_insert_post(array('post_title' => 'Top casino games reviewed', 'post_status' => 'draft'));
}
`,
	},
	{
		name:     "webshell_hex_function_name",
		ext:      ".php",
		knownHit: "webshell_hex_function_name",
		sample: `<?php
function parse_multipart($message, callable $parser) {
    $separator = "\x0d\x0a\x0d\x0a";
    return $parser($message, $separator);
}
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

// expectedRealtimeDetections keeps attacker-shaped and intentional dual-use
// detections out of the false-positive burn-down list. A rendered webmail
// credential form in an account document root is phishing-shaped, while
// Adminer and Tiny File Manager provide high-risk administrative surfaces.
var expectedRealtimeDetections = []struct {
	name   string
	ext    string
	rule   string
	reason string
	sample string
}{
	{
		name:   "packed PHP activation dropper",
		ext:    ".php",
		rule:   "exploit_wp_fake_plugin_installer",
		reason: "activation writes PHP reconstructed from a packed blob",
		sample: `<?php
register_activation_hook(__FILE__, 'seed_templates');
function seed_templates() {
    file_put_contents(plugin_dir_path(__FILE__) . 'cache/tpl.php', gzinflate($packed_template));
}
`,
	},
	{
		name:   "standalone Roundcube credential form",
		ext:    ".html",
		rule:   "phishing_webmail",
		reason: "policy reports a branded credential form in an account document root",
		sample: `<title>Roundcube Webmail Login</title>
<form action="/roundcube/index.php" method="post"><input type="password" name="_pass"></form>
`,
	},
	{
		name:   "stock Adminer",
		ext:    ".php",
		rule:   "webshell_adminer_abuse",
		reason: "policy reports a standalone database administration surface",
		sample: `<?php
/** Adminer 4.8.1 - Database management in a single PHP file. https://www.adminer.org */
`,
	},
	{
		name:   "stock Tiny File Manager",
		ext:    ".php",
		rule:   "webshell_tiny_file_manager",
		reason: "policy reports a standalone authenticated file administration surface",
		sample: `<?php
// Tiny File Manager 2.5.3 - https://tinyfilemanager.github.io
$auth_users = array('admin' => password_hash('changeme', PASSWORD_DEFAULT));
`,
	},
}

func validateControlClaims(t *testing.T) {
	t.Helper()

	var problems []string
	controlNames := make(map[string]bool)
	claimOwners := make(map[string]string)
	for _, control := range benignControls {
		if strings.TrimSpace(control.name) == "" || strings.TrimSpace(control.ext) == "" || strings.TrimSpace(control.sample) == "" {
			problems = append(problems, "benign controls require a name, extension, and sample")
			continue
		}
		if controlNames[control.name] {
			problems = append(problems, "duplicate benign control name "+control.name)
		}
		controlNames[control.name] = true
		if control.knownHit == "" {
			continue
		}
		if control.name != control.knownHit {
			problems = append(problems, control.name+" names false positive "+control.knownHit)
		}
		if owner, exists := claimOwners[control.knownHit]; exists {
			problems = append(problems, control.knownHit+" is claimed by both "+owner+" and "+control.name)
		} else {
			claimOwners[control.knownHit] = control.name
		}
		if _, declared := knownRealtimeFalsePositives[control.knownHit]; !declared {
			problems = append(problems, control.name+" has undeclared false positive "+control.knownHit)
		}
	}
	for rule, reason := range knownRealtimeFalsePositives {
		if strings.TrimSpace(rule) == "" || strings.TrimSpace(reason) == "" {
			problems = append(problems, "false-positive claims require a rule and reason")
		}
		if _, exercised := claimOwners[rule]; !exercised {
			problems = append(problems, rule+" has no reproducing benign control")
		}
	}

	expectedNames := make(map[string]bool)
	for _, control := range expectedRealtimeDetections {
		if strings.TrimSpace(control.name) == "" || strings.TrimSpace(control.ext) == "" || strings.TrimSpace(control.rule) == "" || strings.TrimSpace(control.reason) == "" || strings.TrimSpace(control.sample) == "" {
			problems = append(problems, "expected detections require a name, extension, rule, reason, and sample")
			continue
		}
		if expectedNames[control.name] {
			problems = append(problems, "duplicate expected detection name "+control.name)
		}
		expectedNames[control.name] = true
		if _, admitted := knownRealtimeFalsePositives[control.rule]; admitted {
			problems = append(problems, control.rule+" is both expected and admitted as a false positive")
		}
	}

	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatalf("invalid realtime control claims: %v", problems)
	}
}

// TestRealtimeRulesAgainstBenignControls is the counterpart to the clean-corpus
// gate. The corpus proves a rule is quiet on 15,992 real files; these controls
// exercise realistic shapes that corpus happens not to contain.
func TestRealtimeRulesAgainstBenignControls(t *testing.T) {
	validateControlClaims(t)

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

	for _, control := range benignControls {
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

			matches, err := yaraScanner.ScanBytesChecked([]byte(control.sample))
			if err != nil {
				t.Fatalf("scheduled scan failed: %v", err)
			}
			var scheduled []string
			for _, match := range matches {
				scheduled = append(scheduled, match.RuleName)
			}
			sort.Strings(scheduled)
			if len(scheduled) > 0 {
				t.Errorf("scheduled-scan rules matched legitimate code: %v", scheduled)
			}
		})
	}
}

// TestExpectedRealtimeDetections keeps the controls rejected as benign tied to
// the rule behavior that justifies their classification.
func TestExpectedRealtimeDetections(t *testing.T) {
	validateControlClaims(t)

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	configsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs")
	yamlScanner := signatures.NewScanner(configsDir)
	if err := yamlScanner.LoadError(); err != nil {
		t.Fatalf("loading YAML rules: %v", err)
	}

	for _, control := range expectedRealtimeDetections {
		t.Run(control.name, func(t *testing.T) {
			var fired []string
			wanted := false
			for _, match := range yamlScanner.ScanContent([]byte(control.sample), control.ext) {
				fired = append(fired, match.RuleName)
				if match.RuleName == control.rule {
					wanted = true
				}
			}
			sort.Strings(fired)
			if !wanted {
				t.Errorf("%s did not fire on %s; matches: %v", control.rule, control.reason, fired)
			}
		})
	}
}
