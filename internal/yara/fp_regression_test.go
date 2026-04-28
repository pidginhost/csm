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
