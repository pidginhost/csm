//go:build yara

package yara

import "testing"

// FP reconstruction for the 2026-05-05 Goya theme upload event on
// production. The exploit_revslider YARA rule fired on a wp-content/
// themes/goya/inc/misc.php uploaded by pure-ftpd because the rule's
// condition $a and ($b or $c) accepted "revslider" + "update_plugin"
// substrings -- present in legitimate RevSliderFront integration and the
// site_transient_update_plugins WP filter -- without requiring the
// actual CVE-2014-9734/9735 exploit token pair.

func TestExploitRevsliderYara_GoyaThemeMiscIsNotExploit(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	legit := []byte(`<?php
if ( ! function_exists( 'goya_theme_setup' ) ) {
	function goya_theme_setup() {
		add_theme_support( 'title-tag' );
		if ( class_exists( 'RevSliderFront' ) ) {
			RevSliderFront::add_loader();
		}
	}
}
add_filter( 'site_transient_update_plugins', 'goya_disable_plugin_updates' );
function goya_disable_plugin_updates( $value ) {
	unset( $value->response['revslider/revslider.php'] );
	return $value;
}
`)
	if hasYaraRule(scanner.ScanBytes(legit), "exploit_revslider") {
		t.Error("exploit_revslider YARA FP: matched Goya theme misc.php (RevSliderFront integration + site_transient_update_plugins filter is not the CVE-2014-9734/9735 exploit chain)")
	}
}

func TestExploitRevsliderYara_WPCoreUpdatePluginsFilterIsNotExploit(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	legit := []byte(`<?php
function wp_update_plugins( $extra_stats = array() ) {
	$current = get_site_transient( 'update_plugins' );
	set_site_transient( 'update_plugins', $current );
	return apply_filters( 'site_transient_update_plugins', $current );
}
`)
	if hasYaraRule(scanner.ScanBytes(legit), "exploit_revslider") {
		t.Error("exploit_revslider YARA FP: matched WP core update.php (transient API is not an exploit)")
	}
}

func TestExploitRevsliderYara_RevSliderPluginAjaxRegistrationIsNotExploit(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	legit := []byte(`<?php
class RevSliderFront {
	public static function add_loader() {
		add_action( 'wp_ajax_revslider_ajax_action', array( __CLASS__, 'on_ajax_action' ) );
		add_action( 'wp_ajax_nopriv_revslider_ajax_action', array( __CLASS__, 'on_ajax_action_nopriv' ) );
	}
	public static function on_ajax_action() {
		check_ajax_referer( 'revslider_actions', 'nonce' );
	}
}
`)
	if hasYaraRule(scanner.ScanBytes(legit), "exploit_revslider") {
		t.Error("exploit_revslider YARA FP: matched RevSlider plugin add_action registration (wp_ajax_* hook registration is not an exploit POST body)")
	}
}

func TestExploitRevsliderYara_DocblockMentionIsNotExploit(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	legit := []byte(`<?php
/**
 * Compatibility shim for Revolution Slider.
 *
 * This class disables plugin auto-updates for revslider so the bundled
 * version is not overwritten by the WordPress update_plugins flow.
 */
class Theme_Revslider_Compat {}
`)
	if hasYaraRule(scanner.ScanBytes(legit), "exploit_revslider") {
		t.Error("exploit_revslider YARA FP: matched docblock comment that names revslider and update_plugins (prose, not exploit code)")
	}
}

func TestExploitRevsliderYara_FileUploadExploitURLForm(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	postBody := "action=revslider_ajax_action&client_action=update_plugin&update_file=@shell.zip"
	malicious := []byte(`<?php
$body = '` + postBody + `';
$resp = $sender($url, $body);
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "exploit_revslider") {
		t.Error("exploit_revslider YARA regression: CVE-2014-9735 URL-form file upload exploit was not detected")
	}
}

func TestExploitRevsliderYara_FileUploadExploitReversedParams(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	malicious := []byte(`<?php
$body = 'client_action=update_plugin&action=revslider_ajax_action&update_file=' . $payload;
$resp = $sender($url, $body);
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "exploit_revslider") {
		t.Error("exploit_revslider YARA regression: file upload exploit with reversed param order was not detected")
	}
}

func TestExploitRevsliderYara_FileUploadExploitPHPArrayForm(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	malicious := []byte(`<?php
$args = array(
	'body' => array(
		'action'        => 'revslider_ajax_action',
		'client_action' => 'update_plugin',
		'update_file'   => $shell_zip,
	),
);
$resp = $sender($target, $args);
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "exploit_revslider") {
		t.Error("exploit_revslider YARA regression: PHP-array form of file upload exploit was not detected")
	}
}

func TestExploitRevsliderYara_PathTraversalExploit(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	malicious := []byte(`<?php
$url = 'http://victim.example/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php';
$leak = $fetcher($url);
echo $leak;
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "exploit_revslider") {
		t.Error("exploit_revslider YARA regression: CVE-2014-9734 revslider_show_image path traversal exploit was not detected")
	}
}
