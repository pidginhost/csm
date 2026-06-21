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
	if !strings.Contains(v, "sig=") || !strings.Contains(v, "yara=") {
		t.Errorf("token %q missing sig=/yara= components", v)
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
	if IsContentReverifiable("uid0_account") {
		t.Error("uid0_account is not content-reverifiable")
	}
	if IsContentReverifiable("webshell_content_realtime") {
		t.Error("webshell_content_realtime stays presence-verifiable")
	}
}
