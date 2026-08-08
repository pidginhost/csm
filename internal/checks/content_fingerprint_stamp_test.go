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

func TestStampContentFingerprintPreservesAnalyzedSnapshot(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "changed.js")
	if err := os.WriteFile(p, []byte("replacement content"), 0o600); err != nil {
		t.Fatal(err)
	}

	f := &alert.Finding{
		Check:         "js_keylogger_dataflow",
		FilePath:      p,
		ContentSHA256: "analyzed-snapshot-hash",
		DetectLogic:   "analyzed-snapshot-version",
	}
	StampContentFingerprint(f)

	if f.ContentSHA256 != "analyzed-snapshot-hash" || f.DetectLogic != "analyzed-snapshot-version" {
		t.Fatalf("analyzer fingerprint overwritten from reopened path: %+v", f)
	}

	withoutVersion := &alert.Finding{
		Check:         "js_keylogger_dataflow",
		FilePath:      p,
		ContentSHA256: "analyzed-snapshot-hash",
	}
	StampContentFingerprint(withoutVersion)
	if withoutVersion.ContentSHA256 != "analyzed-snapshot-hash" {
		t.Fatalf("analyzer hash overwritten while adding detection version: %+v", withoutVersion)
	}
	if withoutVersion.DetectLogic != ContentDetectionVersion() {
		t.Fatalf("detection version = %q, want current token", withoutVersion.DetectLogic)
	}
}
