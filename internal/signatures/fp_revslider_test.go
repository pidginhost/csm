package signatures

import "testing"

// FP reconstruction for the 2026-05-05 Goya theme upload event on
// production. The exploit_revslider rule fired on a wp-content/themes/
// goya/inc/misc.php uploaded by pure-ftpd because the rule accepted
// substring "revslider" + substring "update_plugin" -- matches
// "RevSliderFront" and "site_transient_update_plugins" -- without
// requiring the actual CVE-2014-9734/9735 exploit token pair.

func TestExploitRevslider_GoyaThemeMiscIsNotExploit(t *testing.T) {
	scanner := loadRepoScanner(t)

	// Goya/Bridge/Salient WooCommerce themes wrap RevSliderFront
	// integration and disable plugin auto-updates via the
	// site_transient_update_plugins WP filter. Both substrings co-occur
	// in benign theme code; neither names the exploit hook.
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
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "exploit_revslider") {
		t.Error("exploit_revslider FP: matched Goya theme misc.php (RevSliderFront integration + site_transient_update_plugins filter is not the CVE-2014-9734/9735 exploit chain)")
	}
}

func TestExploitRevslider_WPCoreUpdatePluginsFilterIsNotExploit(t *testing.T) {
	scanner := loadRepoScanner(t)

	// WordPress core wp-includes/update.php hooks the
	// site_transient_update_plugins filter; the substring "update_plugin"
	// is part of the transient name, not an exploit token.
	legit := []byte(`<?php
function wp_update_plugins( $extra_stats = array() ) {
	$current = get_site_transient( 'update_plugins' );
	if ( ! is_object( $current ) ) {
		$current = new stdClass;
	}
	set_site_transient( 'update_plugins', $current );
	return apply_filters( 'site_transient_update_plugins', $current );
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "exploit_revslider") {
		t.Error("exploit_revslider FP: matched WP core update.php (set_site_transient/site_transient_update_plugins is the WP transient API, not an exploit)")
	}
}

func TestExploitRevslider_RevSliderPluginAjaxRegistrationIsNotExploit(t *testing.T) {
	scanner := loadRepoScanner(t)

	// Revolution Slider plugin source itself registers the AJAX hook via
	// add_action('wp_ajax_revslider_ajax_action', ...). The hook name
	// alone is not the exploit URL form (action=...&client_action=...).
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
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "exploit_revslider") {
		t.Error("exploit_revslider FP: matched RevSlider plugin add_action registration (wp_ajax_* hook registration is not an exploit POST body)")
	}
}

func TestExploitRevslider_DocblockMentionIsNotExploit(t *testing.T) {
	scanner := loadRepoScanner(t)

	// A theme/plugin readme or docblock that mentions revslider and
	// plugin updates should not match.
	legit := []byte(`<?php
/**
 * Compatibility shim for Revolution Slider.
 *
 * This class disables plugin auto-updates for revslider so the bundled
 * version is not overwritten by the WordPress update_plugins flow.
 */
class Theme_Revslider_Compat {}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "exploit_revslider") {
		t.Error("exploit_revslider FP: matched docblock comment that names revslider and update_plugins (prose, not exploit code)")
	}
}

func TestExploitRevslider_FileUploadExploitURLForm(t *testing.T) {
	scanner := loadRepoScanner(t)

	// Real CVE-2014-9735 file upload exploit: webshell builds an
	// admin-ajax POST body with action + client_action=update_plugin.
	postBody := "action=revslider_ajax_action&client_action=update_plugin&update_file=@shell.zip"
	malicious := []byte(`<?php
$body = '` + postBody + `';
$resp = $sender($url, $body);
`)
	matches := scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "exploit_revslider") {
		t.Error("exploit_revslider regression: CVE-2014-9735 URL-form file upload exploit was not detected")
	}
}

func TestExploitRevslider_FileUploadExploitReversedParams(t *testing.T) {
	scanner := loadRepoScanner(t)

	// Same exploit, parameters reordered.
	malicious := []byte(`<?php
$body = 'client_action=update_plugin&action=revslider_ajax_action&update_file=' . $payload;
$resp = $sender($url, $body);
`)
	matches := scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "exploit_revslider") {
		t.Error("exploit_revslider regression: file upload exploit with reversed param order was not detected")
	}
}

func TestExploitRevslider_FileUploadExploitPHPArrayForm(t *testing.T) {
	scanner := loadRepoScanner(t)

	// PHP wp_remote_post array form of the same exploit body.
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
	matches := scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "exploit_revslider") {
		t.Error("exploit_revslider regression: PHP-array form of file upload exploit was not detected")
	}
}

func TestExploitRevslider_PathTraversalExploit(t *testing.T) {
	scanner := loadRepoScanner(t)

	// Real CVE-2014-9734 arbitrary file download via revslider_show_image
	// + img=../wp-config.php traversal.
	malicious := []byte(`<?php
$url = 'http://victim.example/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php';
$leak = $fetcher($url);
echo $leak;
`)
	matches := scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "exploit_revslider") {
		t.Error("exploit_revslider regression: CVE-2014-9734 revslider_show_image path traversal exploit was not detected")
	}
}
