package checks

import (
	"os"
	"path/filepath"
	"testing"
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
		})
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
