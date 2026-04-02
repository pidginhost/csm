package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
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

func TestIsHighConfidenceRealtimeMatch_LibraryExclusion(t *testing.T) {
	dir := t.TempDir()

	// Create a high-entropy file inside a phpmailer directory
	phpmailerDir := filepath.Join(dir, "server", "phpmailer")
	mkdirTest(t, phpmailerDir)
	libFile := filepath.Join(phpmailerDir, "PHPMailer.php")
	writeTestFile(t, libFile, []byte(generateHighEntropyPHP(8000)))

	f := alert.Finding{
		Details: "Category: webshell\nDescription: Marijuana Shell\nMatched: passthru(",
	}
	if isHighConfidenceRealtimeMatch(f, libFile, nil) {
		t.Error("file in /phpmailer/ path should be excluded even with high entropy")
	}

	// Same file outside library path → should match
	nonLib := filepath.Join(dir, "wp-admin", "maint")
	mkdirTest(t, nonLib)
	evilFile := filepath.Join(nonLib, "index.php")
	writeTestFile(t, evilFile, []byte(generateHighEntropyPHP(8000)))

	f.Details = "Category: dropper\nDescription: goto obfuscation"
	if !isHighConfidenceRealtimeMatch(f, evilFile, nil) {
		t.Error("file outside library paths with high entropy should be high-confidence")
	}
}

func TestIsHighConfidenceRealtimeMatch_VendorExclusion(t *testing.T) {
	dir := t.TempDir()
	vendorDir := filepath.Join(dir, "vendor", "somepackage")
	mkdirTest(t, vendorDir)
	vendorFile := filepath.Join(vendorDir, "obfuscated.php")
	writeTestFile(t, vendorFile, []byte(generateHighEntropyPHP(8000)))

	f := alert.Finding{
		Details: "Category: webshell\nDescription: hex-encoded function",
	}
	if isHighConfidenceRealtimeMatch(f, vendorFile, nil) {
		t.Error("file in /vendor/ path should be excluded")
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
		// The quarantine dir is /opt/csm/quarantine — may not be writable in test.
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
// AES-encrypted webshell — heavy hex encoding with goto obfuscation.
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
