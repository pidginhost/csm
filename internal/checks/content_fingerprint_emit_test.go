package checks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestScanDirStampsContentFingerprint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shell.php")
	content := "<?php eval(base64_decode($_POST['x'])); system($_GET['c']); // pad"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	s := newPHPContentScan(&config.Config{}, nil, false)
	var findings []alert.Finding
	s.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &findings)
	if len(findings) == 0 {
		t.Fatal("expected a finding for malicious shell.php")
	}
	// Select the finding for shell.php in case ordering ever shifts.
	var f *alert.Finding
	for i := range findings {
		if filepath.Base(findings[i].FilePath) == "shell.php" {
			f = &findings[i]
			break
		}
	}
	if f == nil {
		t.Fatal("no finding with FilePath ending in shell.php")
	}
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	if f.ContentSHA256 != want {
		t.Errorf("ContentSHA256 = %q, want %q", f.ContentSHA256, want)
	}
	if f.DetectLogic == "" {
		t.Error("DetectLogic should be populated")
	}
}
