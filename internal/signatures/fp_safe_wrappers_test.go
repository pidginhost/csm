package signatures

import "testing"

// Realtime FP family observed on a production cPanel host: a plugin update
// staged a namespace-prefixed copy of thecodingmachine/safe, whose generated
// wrappers name every native socket and funchand call. Literal patterns are
// matched case-insensitively, so "socket_connect" satisfied network_http_tunnel's
// "CONNECT" literal, and any create_function() wrapper satisfied
// obfuscation_create_function on its own. Both rules carry a qualifying regex
// that never matched; neither required it.

func TestFPSafe_YML_HTTPTunnel_GeneratedSocketWrappers(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte(`<?php
namespace Vendor\Prefixed\Safe;

use Vendor\Prefixed\Safe\Exceptions\SocketsException;

/**
 * Create a Socket instance, and connect it to the provided AddressInfo instance.
 */
function socket_addrinfo_connect($address)
{
    \error_clear_last();
    $safeResult = \socket_addrinfo_connect($address);
    if ($safeResult === false) {
        throw SocketsException::createFromPhpError();
    }
    return $safeResult;
}

function socket_create(int $domain, int $type, int $protocol)
{
    \error_clear_last();
    $safeResult = \socket_create($domain, $type, $protocol);
    if ($safeResult === false) {
        throw SocketsException::createFromPhpError();
    }
    return $safeResult;
}
`)
	if hasRule(s.ScanContent(legit, ".php"), "network_http_tunnel") {
		t.Error("network_http_tunnel FP: matched a generated socket wrapper library")
	}
}

func TestFPSafe_YML_HTTPTunnel_WordPressFTPSockets(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte(`<?php
class ftp_sockets extends ftp_base {
	function _connect($host, $port) {
		$this->_connected = false;
		$this->sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
		if (!socket_connect($this->sock, $host, $port)) {
			$this->PushError('_connect', 'socket connect failed');
			return false;
		}
		$this->_connected = true;
		return true;
	}
}
`)
	if hasRule(s.ScanContent(legit, ".php"), "network_http_tunnel") {
		t.Error("network_http_tunnel FP: matched the FTP sockets class shipped in WordPress core")
	}
}

func TestFPSafe_YML_HTTPTunnel_RawSocketHTTPClient(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte(`<?php
$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_connect($sock, $host, 80);
$req = "GET /api/v1/status HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n";
socket_write($sock, $req, strlen($req));
`)
	if hasRule(s.ScanContent(legit, ".php"), "network_http_tunnel") {
		t.Error("network_http_tunnel FP: matched a plain HTTP client built on sockets")
	}
}

func TestFPSafe_YML_HTTPTunnel_DetectsProxyTunnel(t *testing.T) {
	s := loadRepoScanner(t)
	for name, mal := range map[string][]byte{
		"interpolated": []byte(`<?php
$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_connect($sock, $proxyHost, $proxyPort);
$req = "CONNECT $target:443 HTTP/1.1\r\nHost: $target\r\n\r\n";
socket_write($sock, $req, strlen($req));
`),
		"sprintf": []byte(`<?php
$s = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_connect($s, $_GET['p'], 8080);
socket_write($s, sprintf("CONNECT %s:%d HTTP/1.0\r\n\r\n", $_GET['h'], $_GET['port']));
`),
	} {
		if !hasRule(s.ScanContent(mal, ".php"), "network_http_tunnel") {
			t.Errorf("network_http_tunnel regression: %s CONNECT tunnel not detected", name)
		}
	}
}

func TestFPSafe_YML_CreateFunction_GeneratedWrapper(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte(`<?php
namespace Vendor\Prefixed\Safe;

use Vendor\Prefixed\Safe\Exceptions\FunchandException;

function create_function(string $args, string $code) : string
{
    \error_clear_last();
    $safeResult = \create_function($args, $code);
    if ($safeResult === false) {
        throw FunchandException::createFromPhpError();
    }
    return $safeResult;
}
`)
	if hasRule(s.ScanContent(legit, ".php"), "obfuscation_create_function") {
		t.Error("obfuscation_create_function FP: matched a generated create_function wrapper")
	}
}

func TestFPSafe_YML_CreateFunction_LegacyCallback(t *testing.T) {
	s := loadRepoScanner(t)
	for name, legit := range map[string][]byte{
		"framework callback": []byte(`<?php $sorter = create_function('$a, $b', 'return strcmp($a["name"], $b["name"]);'); usort($items, $sorter);`),
		"polyfill guard":     []byte(`<?php if (!function_exists('create_function')) { function create_function($args, $code) { return null; } }`),
	} {
		if hasRule(s.ScanContent(legit, ".php"), "obfuscation_create_function") {
			t.Errorf("obfuscation_create_function FP: matched %s", name)
		}
	}
}

func TestFPSafe_YML_CreateFunction_DetectsObfuscatedBackdoor(t *testing.T) {
	s := loadRepoScanner(t)
	for name, mal := range map[string][]byte{
		"base64 body":  []byte(`<?php $f = create_function('', base64_decode($_POST['c'])); $f();`),
		"request body": []byte(`<?php $x = create_function('$a', $_REQUEST['code']); $x(1);`),
		"gzinflate":    []byte(`<?php $h = create_function("", gzinflate(base64_decode("q1bKzEspqlSyUlQqSy0qzszPUwIA")));`),
	} {
		if !hasRule(s.ScanContent(mal, ".php"), "obfuscation_create_function") {
			t.Errorf("obfuscation_create_function regression: %s backdoor not detected", name)
		}
	}
}
