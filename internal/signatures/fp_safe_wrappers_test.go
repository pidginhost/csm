package signatures

import (
	"strings"
	"testing"
)

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
		"spaced socket call": []byte(`<?php $s = SoCkEt_CrEaTe (AF_INET, SOCK_STREAM, SOL_TCP); socket_write($s, "CONNECT $h:443 HTTP/1.1\r\n\r\n");`),
	} {
		if !hasRule(s.ScanContent(mal, ".php"), "network_http_tunnel") {
			t.Errorf("network_http_tunnel regression: %s CONNECT tunnel not detected", name)
		}
	}
}

func TestFPSafe_YML_HTTPTunnel_RequestContext(t *testing.T) {
	s := loadRepoScanner(t)
	for name, legit := range map[string]string{
		"request fixture without socket": `<?php $request = "CONNECT example.com:443 HTTP/1.1\r\n\r\n"; assert(parse_request($request)->method === 'CONNECT');`,
		"method name suffix":             `<?php socket_create(AF_INET, SOCK_STREAM, SOL_TCP); $message = "DISCONNECT before sending HTTP/1.1";`,
		"separate statements":            `<?php socket_create(AF_INET, SOCK_STREAM, SOL_TCP); $action = "CONNECT "; $version = "HTTP/1.1";`,
	} {
		t.Run(name, func(t *testing.T) {
			if hasRule(s.ScanContent([]byte(legit), ".php"), "network_http_tunnel") {
				t.Error("unrelated HTTP text reported as a socket tunnel")
			}
		})
	}
}

func TestFPSafe_YML_HTTPTunnel_ConcatenatedRequests(t *testing.T) {
	s := loadRepoScanner(t)
	for name, request := range map[string]string{
		"concatenated":      `"CONNECT " . $h . ":443 HTTP/1.1\r\n\r\n"`,
		"long hostname":     `"CONNECT ` + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + `.example:443 HTTP/1.1\r\n\r\n"`,
		"long expression":   `"CONNECT " . $configuration['upstream']['target_hostname_for_the_requested_connection'] . ":443 HTTP/1.1\r\n\r\n"`,
		"multiline":         "\"CONNECT \" .\n    $h .\n    \":443 HTTP/1.1\\r\\n\\r\\n\"",
		"mixed case":        `"CoNnEcT $h:443 hTtP/1.0\r\n\r\n"`,
		"padded expression": `"CONNECT " .` + strings.Repeat(" ", 1200) + `$h . ":443 HTTP/1.1\r\n\r\n"`,
		"heredoc":           "<<<HTTP\nCONNECT $h:443 HTTP/1.1\n\nHTTP\n",
	} {
		t.Run(name, func(t *testing.T) {
			mal := "<?php $s = socket_create(AF_INET, SOCK_STREAM, SOL_TCP); socket_write($s, " + request + ");"
			if !hasRule(s.ScanContent([]byte(mal), ".php"), "network_http_tunnel") {
				t.Error("constructed CONNECT request not detected")
			}
		})
	}
}

func TestFPSafe_YML_CreateFunction_GeneratedWrapper(t *testing.T) {
	s := loadRepoScanner(t)
	if hasRule(s.ScanContent([]byte(safeCreateFunctionWrapper), ".php"), "obfuscation_create_function") {
		t.Error("obfuscation_create_function FP: matched a generated create_function wrapper")
	}
}

const safeCreateFunctionWrapper = `<?php
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
`

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

func TestFPSafe_YML_CreateFunction_ArgumentContext(t *testing.T) {
	s := loadRepoScanner(t)
	for name, legit := range safeCreateFunctionBenignSamples() {
		t.Run(name, func(t *testing.T) {
			if hasRule(s.ScanContent([]byte(legit), ".php"), "obfuscation_create_function") {
				t.Error("benign callback or unrelated token reported as code execution")
			}
		})
	}
}

func safeCreateFunctionBenignSamples() map[string]string {
	return map[string]string{
		"generated wrapper":      safeCreateFunctionWrapper,
		"framework callback":     `<?php $sorter = create_function('$a, $b', 'return strcmp($a["name"], $b["name"]);'); usort($items, $sorter);`,
		"polyfill guard":         `<?php if (!function_exists('create_function')) { function create_function($args, $code) { return null; } }`,
		"adjacent documentation": "<?php /** create_function() is deprecated.\nUse base64_decode() for decoding data. */",
		"wrapper validation":     "<?php function create_function($args, $code) {\n    if (isset($_SERVER['REQUEST_METHOD'])) { validate($code); }\n    return \\create_function($args, $code);\n}",
		"closed call":            `<?php $callbacks = array(create_function('$x', ''), base64_decode($encoded));`,
		"decoder callback":       `<?php $decoder = create_function('$value', 'return base64_decode($value);');`,
		"decoder name":           `<?php $callback = create_function('', 'return "base64_decode";');`,
		"decoder variable":       `<?php $callback = create_function('', $base64_decode_result);`,
		"parameter default":      `<?php $callback = create_function('$label = "base64_decode"', 'return $label;');`,
		"quoted eval text":       `<?php $callback = create_function('', 'return "eval(";');`,
		"quoted eval argument":   `<?php $callback = create_function('$x', 'return "eval($x)";');`,
		"commented eval":         `<?php $callback = create_function('$x', '/* eval($x) removed */ return $x;');`,
		"line commented eval":    "<?php $callback = create_function('$x', '// eval($x) removed\nreturn $x;');",
		"commented parameter":    `<?php function create_function($args /* unused, $_POST */ , $code) { return ''; }`,
		"commented comma":        `<?php $callback = create_function(/* fixed args, $_POST must not control parameters */ '$x', 'return $x;');`,
		"quoted single eval":     `<?php $callback = create_function('$x', 'return \'eval($x)\';');`,
		"double quoted eval":     `<?php $callback = create_function('$x', "return 'eval(\$x)';");`,
		"double quoted comment":  `<?php $callback = create_function('$x', "/* eval(\$x) */ return 1;");`,
		"method call":            `<?php $object->create_function('', $_POST['code']);`,
		"static method":          `<?php Factory::create_function('', $_POST['code']);`,
		"inner method":           `<?php $callback = create_function('$x', 'return $x->assert($x);');`,
		"inner static method":    `<?php $callback = create_function('$x', 'return Validator::assert($x);');`,
		"inner spaced method":    `<?php $callback = create_function('$x', 'return $x-> /* check */ assert($x);');`,
		"quoted comparison":      `<?php $callback = create_function('$x', 'return ">eval($x)";');`,
		"quoted colon":           `<?php $callback = create_function('$x', 'return ":eval($x)";');`,
		"comment ends at call":   `<?php $callbacks = array(create_function('', /* default */ 'return 1;'), /* decode */ base64_decode($encoded));`,
	}
}

func TestFPSafe_YML_CreateFunction_BodyExpressions(t *testing.T) {
	s := loadRepoScanner(t)
	for name, call := range safeCreateFunctionBodyExpressions() {
		t.Run(name, func(t *testing.T) {
			if !hasRule(s.ScanContent([]byte("<?php $f = "+call+"; $f();"), ".php"), "obfuscation_create_function") {
				t.Error("request-controlled or decoded function body not detected")
			}
		})
	}
}

func safeCreateFunctionBodyExpressions() map[string]string {
	samples := map[string]string{
		"base64 body":             `create_function('', base64_decode($payload))`,
		"inflated body":           `create_function('', gzinflate($payload))`,
		"multiple parameters":     `create_function('$a, $b', $_POST['code'])`,
		"variable parameters":     `create_function($args, $_COOKIE['code'])`,
		"semicolon default":       `create_function('$a = ";"', $_REQUEST['code'])`,
		"long parameters":         `create_function('$a = "` + strings.Repeat("a", 240) + `"', $_GET['code'])`,
		"mixed case":              `CrEaTe_FuNcTiOn ('$a', BaSe64_DeCoDe($payload))`,
		"compressed body":         `create_function('', gzuncompress($payload))`,
		"rotated body":            `create_function('', str_rot13($payload))`,
		"server body":             `create_function('', $_SERVER['HTTP_X_CODE'])`,
		"concatenated body":       `create_function('', '$x = 1; ' . $_POST['code'])`,
		"wrapped body":            `create_function('', (@\base64_decode($payload)))`,
		"multiline body":          "create_function(\n    '$a',\n    $_REQUEST['code']\n)",
		"literal execution":       `create_function('', '$x = 1; eval($_POST["code"]);')`,
		"eval after string":       `create_function('$x', '$label = "literal"; eval($x);')`,
		"eval after comment":      `create_function('$x', '/* legacy code */ eval($x);')`,
		"comment backslash star":  `create_function('$x', '/* regex \* */ eval($x);')`,
		"comment backslash close": `create_function('$x', '/* close \*/eval($x);')`,
		"returned eval":           `create_function('$x', 'return eval($x);')`,
		"logical assert":          `create_function('$x', '$ok or assert($x);')`,
		"global assert":           `create_function('$x', '\\assert($x);')`,
		"single body quotes":      `create_function('$x', '$label = \'literal\'; eval($x);')`,
		"double body eval":        `create_function('$x', "eval(\$x);")`,
		"double body quotes":      `create_function('$x', "\$label = \"literal\"; eval(\$x);")`,
		"parameter comma comment": `create_function('$x' /* parameter, list */, $_POST['code'])`,
		"ternary branch":          `$safe ? $safe :create_function('', $_POST['code'])`,
		"arrow expression":        `fn()=>create_function('', $_POST['code'])`,
		"comparison expression":   `$x>create_function('', $_POST['code'])`,
		"case label":              `function() use ($action) { switch ($action) { case 'run':create_function('', $_POST['code'])(); } }`,
		"divided parameter":       `create_function(chr(100/(1+1)), $_POST['code'])`,
		"commented body":          `create_function('$a' /* parameter */, /* body */ base64_decode($payload))`,
		"line comment":            "create_function('', // body\n $_POST['code'])",
		"escaped default":         `create_function('$a = \'default\'', $_GET['code'])`,
		"interpolated code":       `create_function('', "return {$_POST['code']};")`,
		"nested helper":           `create_function('', trim(base64_decode($payload)))`,
		"grouped concat":          `create_function('', ('$prefix = 1; ' . $_POST['code']))`,
		"array parameters":        `create_function($args[0], $_POST['code'])`,
		"concat parameters":       `create_function('$a' . ', $b', $_POST['code'])`,
		"null parameters":         `create_function(null, $_POST['code'])`,
		"built parameters":        `create_function(implode(',', $args), $_POST['code'])`,
	}
	for name, body := range map[string]string{
		"do":                `do eval($x); while (false);`,
		"case":              `switch (1) { case eval($x): break; }`,
		"include":           `include eval($x);`,
		"include_once":      `include_once eval($x);`,
		"require":           `require eval($x);`,
		"require_once":      `require_once eval($x);`,
		"clone":             `clone eval($x);`,
		"yield from":        `yield from eval($x);`,
		"comparison":        `$y = $x>eval($x);`,
		"shift":             `$y = $x>>eval($x);`,
		"inequality":        `$y = $x<>eval($x);`,
		"string comparison": `$y = "value">eval($x);`,
	} {
		samples["body context "+name] = `create_function('$x', '` + body + `')`
		escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`).Replace(body)
		samples["double body context "+name] = `create_function('$x', "` + escaped + `")`
	}
	return samples
}
