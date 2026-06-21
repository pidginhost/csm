package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

type fakeFindingStore struct {
	findings  []alert.Finding
	dismissed map[string]bool
}

func (s *fakeFindingStore) LatestFindings() []alert.Finding { return s.findings }
func (s *fakeFindingStore) DismissFinding(key string)       { s.dismissed[key] = true }
func (s *fakeFindingStore) DismissLatestFinding(key string) { s.dismissed[key] = true }

func TestReverifyStaleContentFindings(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)

	// Benign file -- current classifier won't flag it; hash matches detection time -> should be dismissed.
	stale := filepath.Join(tmp, "stale.php")
	if err := os.WriteFile(stale, []byte("<?php require_once ABSPATH . 'wp-load.php';"), 0644); err != nil {
		t.Fatal(err)
	}
	// Still-malicious file -> must NOT be dismissed.
	real := filepath.Join(tmp, "real.php")
	if err := os.WriteFile(real, []byte("<?php eval(base64_decode($_POST['x'])); system($_GET['c']);"), 0644); err != nil {
		t.Fatal(err)
	}
	// Benign content now but hash does not match detection time -> must NOT be dismissed.
	modified := filepath.Join(tmp, "modified.php")
	if err := os.WriteFile(modified, []byte("<?php require_once ABSPATH . 'wp-load.php';"), 0644); err != nil {
		t.Fatal(err)
	}

	staleF := alert.Finding{Check: "suspicious_php_content", Message: "m-stale", FilePath: stale, ContentSHA256: FileContentSHA256(stale)}
	realF := alert.Finding{Check: "obfuscated_php", Message: "m-real", FilePath: real, ContentSHA256: FileContentSHA256(real)}
	modF := alert.Finding{Check: "suspicious_php_content", Message: "m-mod", FilePath: modified, ContentSHA256: "deadbeefdeadbeef"}
	nonContentF := alert.Finding{Check: "uid0_account", Message: "m-uid0"} // not content-reverifiable -> skipped

	store := &fakeFindingStore{
		findings:  []alert.Finding{staleF, realF, modF, nonContentF},
		dismissed: map[string]bool{},
	}

	got := ReverifyStaleContentFindings(store)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 dismissal, got %d: %+v", len(got), got)
	}
	if !store.dismissed[staleF.Key()] {
		t.Error("stale (identical-bytes, now-clean) finding should be dismissed")
	}
	if store.dismissed[realF.Key()] {
		t.Error("still-malicious finding must NOT be dismissed")
	}
	if store.dismissed[modF.Key()] {
		t.Error("modified-since-detection finding must NOT be dismissed")
	}
}
