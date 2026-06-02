package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestExtractCategory(t *testing.T) {
	tests := []struct {
		details string
		want    string
	}{
		{"Category: dropper\nDescription: PHP goto obfuscation", "dropper"},
		{"Category: webshell\nDescription: Marijuana Shell", "webshell"},
		{"Category: backdoor\nDescription: create_function", "backdoor"},
		{"Category: mailer\nDescription: forged headers", "mailer"},
		{"no category here", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractCategory(tt.details)
		if got != tt.want {
			t.Errorf("extractCategory(%q) = %q, want %q", tt.details, got, tt.want)
		}
	}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write test file %s: %v", path, err)
	}
}

func mkdirTest(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatalf("failed to create test dir %s: %v", path, err)
	}
}

func TestIsHighConfidenceRealtimeMatch_CategoryFilter(t *testing.T) {
	dir := t.TempDir()
	malware := filepath.Join(dir, "evil.php")
	writeTestFile(t, malware, []byte(generateHighEntropyPHP(8000)))

	// Dropper category → should match
	f := alert.Finding{
		Details: "Category: dropper\nDescription: PHP goto obfuscation\nMatched: goto",
	}
	if !isHighConfidenceRealtimeMatch(f, malware, nil) {
		t.Error("dropper category with high entropy should be high-confidence")
	}

	// Webshell category → should match
	f.Details = "Category: webshell\nDescription: hex-encoded function\nMatched: hex"
	if !isHighConfidenceRealtimeMatch(f, malware, nil) {
		t.Error("webshell category with high entropy should be high-confidence")
	}

	// Backdoor category → should NOT match (not in allowed categories)
	f.Details = "Category: backdoor\nDescription: create_function\nMatched: create_function("
	if isHighConfidenceRealtimeMatch(f, malware, nil) {
		t.Error("backdoor category should not be high-confidence")
	}

	// Mailer category → should NOT match
	f.Details = "Category: mailer\nDescription: forged headers\nMatched: mail("
	if isHighConfidenceRealtimeMatch(f, malware, nil) {
		t.Error("mailer category should not be high-confidence")
	}
}

func TestIsHighConfidenceRealtimeMatch_EntropyFilter(t *testing.T) {
	dir := t.TempDir()
	dropper := alert.Finding{
		Details: "Category: dropper\nDescription: goto obfuscation",
	}

	// Low entropy file (normal PHP) → should NOT match
	normalPHP := filepath.Join(dir, "normal.php")
	writeTestFile(t, normalPHP, []byte(`<?php
class PHPMailer {
    public $CharSet = 'utf-8';
    public $ContentType = 'text/plain';
    public function send() {
        return mail($this->to, $this->Subject, $this->Body);
    }
    // Call mail() in a safe_mode-aware fashion.
    protected function mailPassthru() {
        return true;
    }
}
`))
	if isHighConfidenceRealtimeMatch(dropper, normalPHP, nil) {
		t.Error("normal PHP code (low entropy) should not be high-confidence")
	}

	// High entropy file (obfuscated malware) → should match
	obfuscated := filepath.Join(dir, "obfuscated.php")
	writeTestFile(t, obfuscated, []byte(generateHighEntropyPHP(10000)))
	if !isHighConfidenceRealtimeMatch(dropper, obfuscated, nil) {
		t.Error("obfuscated PHP (high entropy) should be high-confidence")
	}
}

// Confidence is judged by content, not path: an obfuscated webshell hidden
// inside a library directory must still auto-quarantine. The old code skipped
// any file under a known-library path fragment, which let an attacker hide a
// backdoor by planting it under vendor/, phpmailer/, etc.
func TestIsHighConfidenceRealtimeMatch_ObfuscatedWebshellInLibraryDirQuarantined(t *testing.T) {
	dir := t.TempDir()
	phpmailerDir := filepath.Join(dir, "server", "phpmailer")
	mkdirTest(t, phpmailerDir)
	libFile := filepath.Join(phpmailerDir, "PHPMailer.php")
	writeTestFile(t, libFile, []byte(generateHighEntropyPHP(8000)))

	f := alert.Finding{
		Details: "Category: webshell\nDescription: Marijuana Shell\nMatched: passthru(",
	}
	if !isHighConfidenceRealtimeMatch(f, libFile, nil) {
		t.Error("obfuscated webshell under /phpmailer/ must still be quarantined")
	}

	// Same obfuscated content outside any library path → also quarantined.
	nonLib := filepath.Join(dir, "wp-admin", "maint")
	mkdirTest(t, nonLib)
	evilFile := filepath.Join(nonLib, "index.php")
	writeTestFile(t, evilFile, []byte(generateHighEntropyPHP(8000)))

	f.Details = "Category: dropper\nDescription: goto obfuscation"
	if !isHighConfidenceRealtimeMatch(f, evilFile, nil) {
		t.Error("file outside library paths with high entropy should be high-confidence")
	}
}

// A webshell under vendor/ must auto-quarantine: the path is not a free pass.
func TestIsHighConfidenceRealtimeMatch_VendorWebshellQuarantined(t *testing.T) {
	dir := t.TempDir()
	vendorDir := filepath.Join(dir, "vendor", "somepackage")
	mkdirTest(t, vendorDir)
	vendorFile := filepath.Join(vendorDir, "obfuscated.php")
	writeTestFile(t, vendorFile, []byte(generateHighEntropyPHP(8000)))

	f := alert.Finding{
		Details: "Category: webshell\nDescription: hex-encoded function",
	}
	if !isHighConfidenceRealtimeMatch(f, vendorFile, nil) {
		t.Error("obfuscated webshell under /vendor/ must be quarantined")
	}
}

func TestIsHighConfidenceRealtimeMatch_SmallFileExclusion(t *testing.T) {
	dir := t.TempDir()
	tiny := filepath.Join(dir, "tiny.php")
	writeTestFile(t, tiny, []byte(`<?php eval(base64_decode($_POST['x'])); ?>`))

	f := alert.Finding{
		Details: "Category: webshell\nDescription: eval injection",
	}
	if isHighConfidenceRealtimeMatch(f, tiny, nil) {
		t.Error("files under 512 bytes should not be high-confidence (entropy unreliable)")
	}
}

func TestIsHighConfidenceRealtimeMatch_DropperSkipsEntropy(t *testing.T) {
	// Dropper category should auto-quarantine regardless of entropy.
	// The LEVIATHAN goto-obfuscated AES webshell has entropy of only ~3.5
	// because \xNN hex encoding uses a tiny repeating character set.
	dir := t.TempDir()
	hexWebshell := filepath.Join(dir, "index.php")
	writeTestFile(t, hexWebshell, []byte(generateHexEncodedPHP(8000)))

	f := alert.Finding{
		Details: "Category: dropper\nDescription: PHP goto obfuscation\nMatched: goto",
	}
	if !isHighConfidenceRealtimeMatch(f, hexWebshell, nil) {
		t.Error("dropper category should be quarantined even with low entropy (hex-encoded content)")
	}
}

func TestIsHighConfidenceRealtimeMatch_WebshellHexDensity(t *testing.T) {
	// Webshell with low entropy but high hex density should still be caught.
	dir := t.TempDir()
	hexWebshell := filepath.Join(dir, "shell.php")
	writeTestFile(t, hexWebshell, []byte(generateHexEncodedPHP(8000)))

	f := alert.Finding{
		Details: "Category: webshell\nDescription: hex-encoded function\nMatched: hex",
	}
	if !isHighConfidenceRealtimeMatch(f, hexWebshell, nil) {
		t.Error("webshell with high hex density should be high-confidence even with low entropy")
	}
}

func TestHexEncodingDensity(t *testing.T) {
	tests := []struct {
		name    string
		content string
		minDens float64
		maxDens float64
	}{
		{"pure hex", `\x41\x42\x43\x44\x45\x46\x47\x48`, 0.9, 1.1},
		{"normal PHP", `<?php echo "hello world"; function foo() { return 42; } ?>`, 0.0, 0.01},
		{"mixed", `<?php $a = "\x50\x4b\x03\x04"; echo $a; ?>`, 0.2, 0.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := hexEncodingDensity(tt.content)
			if d < tt.minDens || d > tt.maxDens {
				t.Errorf("hexEncodingDensity = %.2f, want between %.2f and %.2f", d, tt.minDens, tt.maxDens)
			}
		})
	}
}

func TestIsHighConfidenceRealtimeMatch_MissingFile(t *testing.T) {
	f := alert.Finding{
		Details: "Category: dropper\nDescription: goto obfuscation",
	}
	if isHighConfidenceRealtimeMatch(f, "/nonexistent/path/evil.php", nil) {
		t.Error("nonexistent file should not be high-confidence")
	}
}

func TestInlineQuarantine_QuarantinesHighConfidence(t *testing.T) {
	dir := t.TempDir()
	malware := filepath.Join(dir, "index.php")
	writeTestFile(t, malware, []byte(generateHighEntropyPHP(10000)))

	f := alert.Finding{
		Details:  "Category: dropper\nDescription: goto obfuscation",
		FilePath: malware,
	}

	qPath, ok := InlineQuarantine(f, malware, nil)
	if !ok {
		// The quarantine dir is /opt/csm/quarantine - may not be writable in test.
		// Verify it's not a validation failure by checking the gate directly.
		if !isHighConfidenceRealtimeMatch(f, malware, nil) {
			t.Fatal("validation gate should pass for high-entropy dropper")
		}
		t.Skip("quarantine dir not writable in test environment (expected on dev)")
	}

	if qPath == "" {
		t.Fatal("quarantine path should not be empty on success")
	}
}

func TestInlineQuarantine_SkipsFalsePositive(t *testing.T) {
	dir := t.TempDir()
	legit := filepath.Join(dir, "PHPMailer.php")
	writeTestFile(t, legit, []byte(`<?php
class PHPMailer {
    public $CharSet = 'utf-8';
    public function send() { return mail($this->to, $this->Subject, $this->Body); }
    // Call mail() in a safe_mode-aware fashion.
    protected function mailPassthru() { return true; }
}
`))

	f := alert.Finding{
		Details:  "Category: webshell\nDescription: Marijuana Shell",
		FilePath: legit,
	}
	_, ok := InlineQuarantine(f, legit, nil)
	if ok {
		t.Error("InlineQuarantine should NOT quarantine low-entropy legitimate PHP")
	}

	// File should still exist
	if _, err := os.Stat(legit); err != nil {
		t.Error("legitimate file should not be removed")
	}
}

// generateHexEncodedPHP creates PHP content that mimics the LEVIATHAN
// AES-encrypted webshell - heavy hex encoding with goto obfuscation.
// This has LOW Shannon entropy (~3.5) but HIGH hex density (>30%).
func generateHexEncodedPHP(size int) string {
	var b strings.Builder
	b.WriteString("<?php\n goto o8ip9;")
	fragments := []string{
		`$t7Mx9="\131\x50\103\x4f\114\155\67\170\x58\x4a\142\114\x35\67\x4c\x51\145\x54\104\53";`,
		`$yR5Wo="\x31\62\x33\64\x35\66\x37\x38\x39\x30\141\x62\143\144\x65\146";`,
		`$f5s8i=openssl_decrypt($t7Mx9,"\101\x45\123\x2d\61\62\70\x2d\x45\103\102",$yR5Wo,0);`,
		`ini_set("\x64\x69\163\x70\x6c\x61\x79\x5f\x65\x72\x72\x6f\x72\x73",0);`,
		`if($_SERVER["\122\x45\121\125\x45\123\x54\137\115\x45\x54\x48\117\104"]==="\x50\x4f\123\124"){`,
		`eval("\77\x3e".$f5s8i);`,
	}
	for b.Len() < size {
		for _, frag := range fragments {
			b.WriteString(frag)
			if b.Len() >= size {
				break
			}
		}
	}
	return b.String()
}

// generateHighEntropyPHP creates PHP content that mimics goto-obfuscated
// malware with high Shannon entropy (>4.8). Uses many distinct fragments
// to avoid repetition-induced entropy reduction.
func generateHighEntropyPHP(size int) string {
	var b strings.Builder
	b.WriteString("<?php\n goto v8k7T;")
	fragments := []string{
		`tWgqB:goto Og31z;dGB2A:PzsUc:goto WlstR;pSGLA:GCxUl:goto CsDy8;`,
		`$a="\x50\x4b\x03\x04\x48\x65\x6c\x6c\x6f\x57\x6f\x72\x6c\x64";`,
		`if($_SERVER["\122\x45\121\125\x45\123\x54\137\115\x45\x54\x48\117\104"]==="\x50\x4f\123\124"){`,
		`J941D:if(isset($_POST["\163\145\141\x72\143\x68\x5f\144\151\x72"])&&!empty($_POST["\144\151\x72\x5f\160\141\x74\150"])){goto J14gd;}`,
		`$t7Mx9="\131\x50\103\x4f\114\155\67\170\x58\x4a\142\114\x35\67\x4c\x51\145\x54\104\53";`,
		`EDKRo:blJH1:goto U91CH;YAeyF:goto wCJPp;goto xxWFy;rt_CK:goto sFEEc;goto uDazS;`,
		`$f5s8i=openssl_decrypt($t7Mx9,"\101\x45\123\x2d\61\62\70\x2d\x45\103\102",$yR5Wo,0);`,
		`mnTR2:iCrZ7:goto qf4NS;Z_yL2:tCcfC:goto nwHJo;RObld:goto Zh0pN;goto DP0Yz;`,
		`$yR5Wo="\x31\62\x33\64\x35\66\x37\x38\x39\x30\141\x62\143\144\x65\146";`,
		`vqMRT:MibLm:goto go03i;Vo4Ic:yCyiv:goto qlPrr;VrAQZ:sYDPa:goto mWpQb;`,
	}
	for b.Len() < size {
		for _, frag := range fragments {
			b.WriteString(frag)
			if b.Len() >= size {
				break
			}
		}
	}
	return b.String()
}

// Regression: WPML wpml_zip.php has measured entropy 5.25 (a handful of
// ZIP magic-byte constants raise per-byte entropy above the old 4.8 gate)
// but is clearly legitimate PHPZip library code. The 4.8 threshold was too
// permissive. Breakdance google-fonts.php measures 4.90 -- this fixture
// mimics that shape: a commented PHP class with mixed identifiers, a
// few \xNN binary constants, and natural-language docstrings. Lands near
// entropy 5.0 with hex density ~3% (well under the 20% hex arm).
func TestIsHighConfidenceRealtimeMatch_EntropyBand_4_8_to_5_5(t *testing.T) {
	dir := t.TempDir()
	dropper := alert.Finding{Details: "Category: dropper\nDescription: test"}

	borderline := filepath.Join(dir, "libcode.php")
	writeTestFile(t, borderline, []byte(libLikePHPFixture()))

	if isHighConfidenceRealtimeMatch(dropper, borderline, nil) {
		t.Error("entropy ~5.0 library code must NOT pass the high-confidence gate after tightening to >=5.5")
	}
}

func libLikePHPFixture() string {
	return `<?php
/**
 * Class to manage a Zip archive.
 *
 * This implementation follows the PKWARE ZIP specification.
 * Provides methods for adding files, setting metadata, and finalising
 * the archive into a single byte stream or temporary file.
 *
 * @author A. Grandt
 * @license LGPL
 */
class Zip {
    const ZIP_LOCAL_FILE_HEADER = "\x50\x4b\x03\x04";
    const ZIP_CENTRAL_FILE_HEADER = "\x50\x4b\x01\x02";
    const ZIP_END_OF_CENTRAL_DIRECTORY = "\x50\x4b\x05\x06";
    const ATTR_VERSION_TO_EXTRACT = "\x14\x00";

    private $zipMemoryThreshold = 1048576;
    private $zipData = null;
    private $zipFile = null;
    private $centralDirectory = array();
    private $endOfCentralDirectory = "";

    public function __construct() {
        // Default constructor: initialise the in-memory ZIP buffer.
        $this->zipData = "";
    }

    public function addFile($data, $filePath, $timestamp = 0, $fileComment = null) {
        // Compress with deflate and append a local file header plus
        // the compressed payload to the in-memory buffer. This mirrors
        // the behaviour described in APPNOTE.TXT section 4.3.
        if (is_resource($data)) {
            rewind($data);
            $data = stream_get_contents($data);
        }
        $compressed = gzdeflate($data, 9);
        $crc32 = crc32($data);
        $size = strlen($data);
        $compSize = strlen($compressed);
        // Emit the header record and payload.
        $header = self::ZIP_LOCAL_FILE_HEADER;
        $header .= self::ATTR_VERSION_TO_EXTRACT;
        $header .= pack("v", 0);
        $header .= pack("v", 8);
        $header .= pack("V", $crc32);
        $this->zipData .= $header;
        $this->zipData .= $compressed;
    }

    public function setZipFile($fileName) {
        // Switch from memory storage to temp-file storage once the
        // buffered payload exceeds zipMemoryThreshold.
        $this->zipFile = fopen($fileName, "wb");
        fwrite($this->zipFile, $this->zipData);
        $this->zipData = null;
    }
}
`
}

// Real WPML/Breakdance library files carry binary magic-byte constants that
// raise entropy/hex density but are inert data with no obfuscated execution.
// They must NOT be quarantined -- and that must hold on any path, not because
// the path is allowlisted. Conversely, obfuscated malware planted under those
// same plugin paths must be quarantined.
func TestIsHighConfidenceRealtimeMatch_LibraryContentNotPath(t *testing.T) {
	dir := t.TempDir()
	pluginPaths := []string{
		"wp-content/plugins/sitepress-multilingual-cms/inc/wpml_zip.php",
		"wp-content/plugins/wpml-translation-management/inc/wpml_zip.php",
		"wp-content/plugins/breakdance/plugin/fonts/integrations/google-fonts/google-fonts.php",
	}
	f := alert.Finding{Details: "Category: webshell\nDescription: test"}

	for _, rel := range pluginPaths {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		// Inert library code: not quarantined regardless of path.
		writeTestFile(t, full, []byte(libLikePHPFixture()))
		if isHighConfidenceRealtimeMatch(f, full, nil) {
			t.Errorf("inert library content at %q must not be quarantined", rel)
		}
		// Obfuscated malware under the same plugin path: quarantined.
		writeTestFile(t, full, []byte(generateHighEntropyPHP(8000)))
		if !isHighConfidenceRealtimeMatch(f, full, nil) {
			t.Errorf("obfuscated malware at %q must be quarantined", rel)
		}
	}
}

func TestHasObfuscatedExecutionSignal(t *testing.T) {
	// goto-spaghetti control-flow obfuscation.
	if !hasObfuscatedExecutionSignal(generateHighEntropyPHP(8000)) {
		t.Error("goto-obfuscated content must signal")
	}
	// decoder + executor combo.
	if !hasObfuscatedExecutionSignal(generateHexEncodedPHP(8000)) {
		t.Error("decoder+executor content must signal")
	}
	if !hasObfuscatedExecutionSignal("<?php eval(gzinflate(base64_decode($x))); ?>") {
		t.Error("eval+decoder one-liner must signal")
	}
	// Inert library data: magic-byte constants, gzdeflate writer, no executor.
	if hasObfuscatedExecutionSignal(libLikePHPFixture()) {
		t.Error("inert ZIP library data must not signal")
	}
	// A decoder with no executor is not enough on its own.
	if hasObfuscatedExecutionSignal("<?php $x = base64_decode($raw); echo strlen($x);") {
		t.Error("decoder without executor must not signal")
	}
	// Hex-escaped function names are usually concatenated without spaces around
	// the dot operator. That shape must still signal.
	if !hasObfuscatedExecutionSignal(noSpaceHexConcatFunctionFixture()) {
		t.Error("hex-escaped no-space function-name concat must signal")
	}
	// A generic callback in code that also decodes data is not an executor.
	if hasObfuscatedExecutionSignal(benignHighHexCallbackFixture()) {
		t.Error("benign decoder plus callback library code must not signal")
	}
	if hasObfuscatedExecutionSignal(benignHighHexCallUserFuncFixture()) {
		t.Error("benign decoder plus call_user_func callback must not signal")
	}
	if !hasObfuscatedExecutionSignal(`<?php call_user_func("assert", base64_decode($x)); ?>`) {
		t.Error("dangerous literal callback executor must signal")
	}
}

func TestIsHighConfidenceRealtimeMatch_BenignHighHexCallbackLibrary(t *testing.T) {
	content := benignHighHexCallbackFixture()
	if len(content) < 512 || hexEncodingDensity(content) <= 0.20 {
		t.Fatalf("test fixture must exercise the high-hex arm, len=%d density=%.2f", len(content), hexEncodingDensity(content))
	}

	f := alert.Finding{Details: "Category: dropper\nDescription: test"}
	if isHighConfidenceRealtimeMatch(f, "/home/alice/public_html/vendor/lib.php", []byte(content)) {
		t.Error("benign high-hex callback library code must not be high confidence")
	}
}

func noSpaceHexConcatFunctionFixture() string {
	var b strings.Builder
	b.WriteString("<?php\n")
	for b.Len() < 768 {
		b.WriteString(`$f="\x65"."\x76"."\x61"."\x6c";`)
	}
	return b.String()
}

func benignHighHexCallbackFixture() string {
	return benignHighHexCallbackFixtureWithCall("    return $callback($decoded);\n")
}

func benignHighHexCallUserFuncFixture() string {
	return benignHighHexCallbackFixtureWithCall("    return call_user_func($callback, $decoded);\n")
}

func benignHighHexCallbackFixtureWithCall(callLine string) string {
	var b strings.Builder
	b.WriteString("<?php\n")
	b.WriteString("function decode_library_blob($raw, $callback) {\n")
	b.WriteString("    $decoded = base64_decode($raw);\n")
	b.WriteString(callLine)
	b.WriteString("}\n")
	b.WriteString(`const ZIP_MAGIC = "`)
	for b.Len() < 1024 {
		b.WriteString(`\x50\x4b\x03\x04`)
	}
	b.WriteString(`";`)
	return b.String()
}
