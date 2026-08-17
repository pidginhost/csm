package checks

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContentDetectionVersionFormat(t *testing.T) {
	v := ContentDetectionVersion()
	if !strings.HasPrefix(v, fmt.Sprintf("php=%d;", ContentLogicVersion)) {
		t.Errorf("token %q missing php=%d prefix", v, ContentLogicVersion)
	}
	if !strings.Contains(v, fmt.Sprintf("scan=%d;", ContentScannerVersion)) {
		t.Errorf("token %q missing scan=%d component", v, ContentScannerVersion)
	}
	if !strings.Contains(v, "sig=") || !strings.Contains(v, "yara=") {
		t.Errorf("token %q missing sig=/yara= components", v)
	}
}

func TestContentScannerVersionIncludesBackendArchiveGuard(t *testing.T) {
	const backendArchiveGuardVersion = 2
	if ContentScannerVersion < backendArchiveGuardVersion {
		t.Fatalf("ContentScannerVersion = %d, want at least %d so existing archive findings are re-checked", ContentScannerVersion, backendArchiveGuardVersion)
	}
}

func TestContentScannerVersionIncludesPhpsSourceRouting(t *testing.T) {
	const phpsSourceRoutingVersion = 4
	if ContentScannerVersion < phpsSourceRoutingVersion {
		t.Fatalf("ContentScannerVersion = %d, want at least %d for .phps source routing", ContentScannerVersion, phpsSourceRoutingVersion)
	}
}

func TestFileContentSHA256MatchesStdlib(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.php")
	body := []byte("<?php echo 1;")
	if err := os.WriteFile(p, body, 0644); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%x", sha256.Sum256(body))
	if got := FileContentSHA256(p); got != want {
		t.Errorf("FileContentSHA256 = %q want %q", got, want)
	}
	if got := FileContentSHA256(filepath.Join(dir, "missing.php")); got != "" {
		t.Errorf("missing file should hash to empty, got %q", got)
	}
}

func TestAnalyzePHPContentWithFingerprintMatchesFileContentSHA256(t *testing.T) {
	prefix := []byte("<?php echo 'ok';\n")
	cases := []struct {
		name     string
		size     int
		wantHash bool
	}{
		{name: "small", size: len(prefix) + 64, wantHash: true},
		{name: "between-analysis-window-and-cap", size: phpContentReadSize + 4096, wantHash: true},
		{name: "above-cap", size: contentFingerprintMaxBytes + 1, wantHash: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "f.php")
			body := bytes.Repeat([]byte("A"), tc.size)
			copy(body, prefix)
			if err := os.WriteFile(p, body, 0644); err != nil {
				t.Fatal(err)
			}

			result, got := analyzePHPContentWithFingerprint(p)
			if !result.readOK {
				t.Fatal("analyzePHPContentWithFingerprint readOK = false")
			}

			want := FileContentSHA256(p)
			if got != want {
				t.Fatalf("fingerprint = %q, want FileContentSHA256 %q", got, want)
			}
			if tc.wantHash && got == "" {
				t.Fatal("fingerprint is empty, want hash below cap")
			}
			if !tc.wantHash && got != "" {
				t.Fatalf("fingerprint = %q, want empty hash above cap", got)
			}
		})
	}
}

func TestIsContentReverifiable(t *testing.T) {
	if !IsContentReverifiable("suspicious_php_content") {
		t.Error("suspicious_php_content should be content-reverifiable")
	}
	if !IsContentReverifiable("js_keylogger_dataflow") {
		t.Error("js_keylogger_dataflow should be content-reverifiable")
	}
	if IsContentReverifiable("uid0_account") {
		t.Error("uid0_account is not content-reverifiable")
	}
	if IsContentReverifiable("webshell_content_realtime") {
		t.Error("webshell_content_realtime stays presence-verifiable")
	}
}

func TestContentDetectionVersionIncludesJSTaintComponent(t *testing.T) {
	v := ContentDetectionVersion()
	if !strings.Contains(v, fmt.Sprintf("jstaint=%d", JSTaintLogicVersion)) {
		t.Errorf("token %q missing jstaint=%d component", v, JSTaintLogicVersion)
	}
}

// TestContentDetectionVersionTokenJSTaintSensitivity proves the token actually
// depends on the JS analyzer version: two different values must produce two
// different tokens, so a version bump forces the daemon sweep to re-verify.
func TestContentDetectionVersionTokenJSTaintSensitivity(t *testing.T) {
	a := contentDetectionVersionToken(1, 2, 3, 4, 1)
	b := contentDetectionVersionToken(1, 2, 3, 4, 2)
	if a == b {
		t.Fatalf("tokens identical for different jstaint versions: %q", a)
	}
	if !strings.Contains(a, "jstaint=1") || !strings.Contains(b, "jstaint=2") {
		t.Fatalf("tokens %q / %q do not carry their jstaint component", a, b)
	}
}
