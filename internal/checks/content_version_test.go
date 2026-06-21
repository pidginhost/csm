package checks

import (
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

func TestIsContentReverifiable(t *testing.T) {
	if !IsContentReverifiable("suspicious_php_content") {
		t.Error("suspicious_php_content should be content-reverifiable")
	}
	if IsContentReverifiable("uid0_account") {
		t.Error("uid0_account is not content-reverifiable")
	}
}
