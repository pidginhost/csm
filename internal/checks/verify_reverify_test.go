package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/yara"
)

func TestReverifyContentFinding(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)

	// Benign file the current heuristic does NOT flag.
	benign := filepath.Join(tmp, "benign.php")
	if err := os.WriteFile(benign, []byte("<?php require_once ABSPATH . 'wp-load.php';"), 0644); err != nil {
		t.Fatal(err)
	}
	benignHash := FileContentSHA256(benign)

	// Genuinely malicious file the current heuristic DOES flag (>=2 indicators).
	mal := filepath.Join(tmp, "mal.php")
	if err := os.WriteFile(mal, []byte("<?php eval(base64_decode($_POST['x'])); system($_GET['c']);"), 0644); err != nil {
		t.Fatal(err)
	}
	malHash := FileContentSHA256(mal)

	cases := []struct {
		name           string
		in             VerifyInput
		wantChecked    bool
		wantResolved   bool
		detailContains string
	}{
		{"gone", VerifyInput{Check: "suspicious_php_content", Path: filepath.Join(tmp, "nope.php"), ContentSHA256: "x"}, true, true, "no longer present"},
		{"same-hash-now-clean", VerifyInput{Check: "suspicious_php_content", Path: benign, ContentSHA256: benignHash}, true, true, "no longer flagged"},
		{"changed-hash-now-clean", VerifyInput{Check: "suspicious_php_content", Path: benign, ContentSHA256: "deadbeef"}, true, false, "modified since detection"},
		{"legacy-no-hash", VerifyInput{Check: "suspicious_php_content", Path: benign, ContentSHA256: ""}, true, false, "no detection-time fingerprint"},
		{"still-flagged", VerifyInput{Check: "obfuscated_php", Path: mal, ContentSHA256: malHash}, true, false, "still flagged"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := reverifyContentFinding(c.in)
			if res.Checked != c.wantChecked || res.Resolved != c.wantResolved {
				t.Fatalf("%s: got %+v want checked=%v resolved=%v", c.name, res, c.wantChecked, c.wantResolved)
			}
			if c.detailContains != "" && !strings.Contains(res.Detail, c.detailContains) {
				t.Fatalf("%s: detail = %q, want substring %q", c.name, res.Detail, c.detailContains)
			}
		})
	}
}

func TestLocationContentChecksStayPresenceBased(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)

	p := filepath.Join(tmp, "wp-content", "uploads", "clean.php")
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("<?php echo 'clean';"), 0644); err != nil {
		t.Fatal(err)
	}

	res := VerifyFindingInput(VerifyInput{
		Check:         "php_in_uploads_realtime",
		Path:          p,
		ContentSHA256: FileContentSHA256(p),
	})
	if !res.Checked || res.Resolved {
		t.Fatalf("location finding should remain unresolved while file exists, got %+v", res)
	}
	if !strings.Contains(res.Detail, "still present") {
		t.Fatalf("detail = %q, want presence verifier detail", res.Detail)
	}
}

func TestRealtimePHPHeuristicChecksStayPresenceBased(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)

	p := filepath.Join(tmp, "clean.php")
	if err := os.WriteFile(p, []byte("<?php echo 'clean';"), 0644); err != nil {
		t.Fatal(err)
	}
	hash := FileContentSHA256(p)

	for _, check := range []string{
		"webshell_content_realtime",
		"obfuscated_php_realtime",
		"php_dropper_realtime",
	} {
		t.Run(check, func(t *testing.T) {
			res := VerifyFindingInput(VerifyInput{
				Check:         check,
				Path:          p,
				ContentSHA256: hash,
			})
			if !res.Checked || res.Resolved {
				t.Fatalf("realtime PHP heuristic finding should remain unresolved while file exists, got %+v", res)
			}
			if !strings.Contains(res.Detail, "still present") {
				t.Fatalf("detail = %q, want presence verifier detail", res.Detail)
			}
		})
	}
}

func TestContentSnapshotRequiresSameFileIdentity(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "clean.php")
	if err := os.WriteFile(p, []byte("<?php echo 'clean';"), 0644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("<?php echo 'clean';"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readContentSnapshotForReverify(p, info); err == nil {
		t.Fatal("snapshot after inode swap succeeded, want failure")
	}
}

func TestContentReverifyReadFailureFailsClosed(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)

	p := filepath.Join(tmp, "ghost.php")
	if err := os.WriteFile(p, []byte("<?php echo 'clean';"), 0644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{lstat: func(name string) (os.FileInfo, error) {
		if name == p {
			return info, nil
		}
		return os.Lstat(name)
	}})

	res := reverifyContentFinding(VerifyInput{
		Check:         "suspicious_php_content",
		Path:          p,
		ContentSHA256: "recordedhash",
	})
	if res.Checked || res.Resolved {
		t.Fatalf("read failure should fail closed, got %+v", res)
	}
	if !strings.Contains(res.Detail, "cannot read file") {
		t.Fatalf("detail = %q, want read failure", res.Detail)
	}
}

func TestContentReverifyOversizedFileDoesNotResolve(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)

	p := filepath.Join(tmp, "large.php")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(contentFingerprintMaxBytes + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	res := reverifyContentFinding(VerifyInput{
		Check:         "suspicious_php_content",
		Path:          p,
		ContentSHA256: "recordedhash",
	})
	if !res.Checked || res.Resolved {
		t.Fatalf("oversized file with empty current hash should stay unresolved, got %+v", res)
	}
	if !strings.Contains(res.Detail, "modified since detection") {
		t.Fatalf("detail = %q, want sha mismatch detail", res.Detail)
	}
}

func TestContentReverifyScannerUnavailableFailsClosed(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	origSig := contentSignatureScanner
	origYARA := contentYARAScanner
	contentSignatureScanner = func() *signatures.Scanner { return nil }
	contentYARAScanner = func() yara.Backend { return nil }
	t.Cleanup(func() {
		contentSignatureScanner = origSig
		contentYARAScanner = origYARA
	})

	p := filepath.Join(tmp, "clean.php")
	if err := os.WriteFile(p, []byte("<?php echo 'clean';"), 0644); err != nil {
		t.Fatal(err)
	}
	hash := FileContentSHA256(p)

	res := reverifyContentFinding(VerifyInput{Check: "signature_match_realtime", Path: p, ContentSHA256: hash})
	if res.Checked || res.Resolved {
		t.Fatalf("missing signature scanner should fail closed, got %+v", res)
	}
	if !strings.Contains(res.Detail, "signature scanner unavailable") {
		t.Fatalf("detail = %q, want scanner unavailable", res.Detail)
	}

	res = reverifyContentFinding(VerifyInput{Check: "yara_match_realtime", Path: p, ContentSHA256: hash})
	if res.Checked || res.Resolved {
		t.Fatalf("missing YARA scanner should fail closed, got %+v", res)
	}
	if !strings.Contains(res.Detail, "YARA scanner unavailable") {
		t.Fatalf("detail = %q, want scanner unavailable", res.Detail)
	}
}

func TestVerifyFindingInputDispatchesReverify(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	p := filepath.Join(tmp, "b.php")
	if err := os.WriteFile(p, []byte("<?php require_once ABSPATH . 'wp-load.php';"), 0644); err != nil {
		t.Fatal(err)
	}
	res := VerifyFindingInput(VerifyInput{Check: "suspicious_php_content", Message: "Suspicious PHP content detected: " + p, Path: p, ContentSHA256: FileContentSHA256(p)})
	if !res.Checked || !res.Resolved {
		t.Errorf("identical-bytes-now-clean should resolve, got %+v", res)
	}
}
