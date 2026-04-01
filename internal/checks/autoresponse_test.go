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
	if !isHighConfidenceRealtimeMatch(f, malware) {
		t.Error("dropper category with high entropy should be high-confidence")
	}

	// Webshell category → should match
	f.Details = "Category: webshell\nDescription: hex-encoded function\nMatched: hex"
	if !isHighConfidenceRealtimeMatch(f, malware) {
		t.Error("webshell category with high entropy should be high-confidence")
	}

	// Backdoor category → should NOT match (not in allowed categories)
	f.Details = "Category: backdoor\nDescription: create_function\nMatched: create_function("
	if isHighConfidenceRealtimeMatch(f, malware) {
		t.Error("backdoor category should not be high-confidence")
	}

	// Mailer category → should NOT match
	f.Details = "Category: mailer\nDescription: forged headers\nMatched: mail("
	if isHighConfidenceRealtimeMatch(f, malware) {
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
	if isHighConfidenceRealtimeMatch(dropper, normalPHP) {
		t.Error("normal PHP code (low entropy) should not be high-confidence")
	}

	// High entropy file (obfuscated malware) → should match
	obfuscated := filepath.Join(dir, "obfuscated.php")
	writeTestFile(t, obfuscated, []byte(generateHighEntropyPHP(10000)))
	if !isHighConfidenceRealtimeMatch(dropper, obfuscated) {
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
	if isHighConfidenceRealtimeMatch(f, libFile) {
		t.Error("file in /phpmailer/ path should be excluded even with high entropy")
	}

	// Same file outside library path → should match
	nonLib := filepath.Join(dir, "wp-admin", "maint")
	mkdirTest(t, nonLib)
	evilFile := filepath.Join(nonLib, "index.php")
	writeTestFile(t, evilFile, []byte(generateHighEntropyPHP(8000)))

	f.Details = "Category: dropper\nDescription: goto obfuscation"
	if !isHighConfidenceRealtimeMatch(f, evilFile) {
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
	if isHighConfidenceRealtimeMatch(f, vendorFile) {
		t.Error("file in /vendor/ path should be excluded")
	}
}

func TestIsHighConfidenceRealtimeMatch_SmallFileExclusion(t *testing.T) {
	dir := t.TempDir()
	tiny := filepath.Join(dir, "tiny.php")
	// A short file with diverse characters can have high entropy but
	// should NOT be quarantined — entropy is unreliable below 512 bytes.
	writeTestFile(t, tiny, []byte(`<?php eval(base64_decode($_POST['x'])); ?>`))

	f := alert.Finding{
		Details: "Category: webshell\nDescription: eval injection",
	}
	if isHighConfidenceRealtimeMatch(f, tiny) {
		t.Error("files under 512 bytes should not be high-confidence (entropy unreliable)")
	}
}

func TestIsHighConfidenceRealtimeMatch_MissingFile(t *testing.T) {
	f := alert.Finding{
		Details: "Category: dropper\nDescription: goto obfuscation",
	}
	if isHighConfidenceRealtimeMatch(f, "/nonexistent/path/evil.php") {
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

	qPath, ok := InlineQuarantine(f, malware)
	if !ok {
		// The quarantine dir is /opt/csm/quarantine — may not be writable in test.
		// Verify it's not a validation failure by checking the gate directly.
		if !isHighConfidenceRealtimeMatch(f, malware) {
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
	_, ok := InlineQuarantine(f, legit)
	if ok {
		t.Error("InlineQuarantine should NOT quarantine low-entropy legitimate PHP")
	}

	// File should still exist
	if _, err := os.Stat(legit); err != nil {
		t.Error("legitimate file should not be removed")
	}
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
