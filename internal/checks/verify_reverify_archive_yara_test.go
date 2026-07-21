//go:build yara

package checks

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pidginhost/csm/internal/yara"
)

func TestContentReverifyCompressedArchiveResolvesYARAFinding(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	rulesDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs")
	scanner, err := yara.NewScanner(rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("<?php system($_POST['cmd']);")
	hits, err := scanner.ScanBytesChecked(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) == 0 {
		t.Fatal("extracted PHP payload must remain detectable")
	}

	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	orig := contentYARAScanner
	contentYARAScanner = func() yara.Backend { return scanner }
	t.Cleanup(func() { contentYARAScanner = orig })

	p := filepath.Join(tmp, "backup.zip")
	archive := append([]byte{'P', 'K', 0x03, 0x04}, payload...)
	if err := os.WriteFile(p, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	res := reverifyContentFinding(VerifyInput{
		Check:         "yara_match_scheduled",
		Path:          p,
		ContentSHA256: FileContentSHA256(p),
	})
	if !res.Checked || !res.Resolved {
		t.Fatalf("identical compressed archive finding should resolve, got %+v", res)
	}
}
