package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestStampContentFingerprint(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.php")
	if err := os.WriteFile(p, []byte("<?php eval(base64_decode($_POST['x']));"), 0644); err != nil {
		t.Fatal(err)
	}
	// content-reverifiable + path -> stamped
	f := &alert.Finding{Check: "yara_match_realtime", FilePath: p}
	StampContentFingerprint(f)
	if f.ContentSHA256 != FileContentSHA256(p) || f.DetectLogic == "" {
		t.Errorf("content finding not stamped: %+v", f)
	}
	// non-content -> untouched
	g := &alert.Finding{Check: "uid0_account", FilePath: p}
	StampContentFingerprint(g)
	if g.ContentSHA256 != "" || g.DetectLogic != "" {
		t.Errorf("non-content finding should not be stamped: %+v", g)
	}
	// empty path -> untouched
	h := &alert.Finding{Check: "yara_match_realtime"}
	StampContentFingerprint(h)
	if h.ContentSHA256 != "" || h.DetectLogic != "" {
		t.Errorf("pathless finding should not be stamped: %+v", h)
	}
}
