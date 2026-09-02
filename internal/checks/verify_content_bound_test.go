package checks

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/signatures"
)

// The re-verify sweep runs automatically over every stored content finding
// whenever the detection version changes. The signature and YARA branches
// read the flagged file whole, so an attacker who appends gigabytes to a
// file that is already flagged makes the sweep allocate several copies of
// it and OOM the daemon. Those branches must honour the full-scan ceiling
// and leave the finding unresolved instead of reading past it.
func TestContentStillMatchesRefusesFilesAboveScanCeiling(t *testing.T) {
	dir := t.TempDir()
	withQuarantineAllowedRoots(t, dir)
	rules := "version: 1\nrules:\n  - name: test_marker\n    description: t\n    severity: high\n    category: obfuscation\n    file_types: [\".php\"]\n    patterns: [\"EVIL_MARKER_B\"]\n    min_match: 1\n"
	if err := os.WriteFile(filepath.Join(dir, "r.yml"), []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	signatures.Init(dir)
	t.Cleanup(func() { signatures.Init(t.TempDir()) })

	prev := config.Active()
	cfg := &config.Config{}
	cfg.Thresholds.FullScanMaxFileMB = 1
	config.SetActive(cfg)
	t.Cleanup(func() { config.SetActive(prev) })

	path := filepath.Join(dir, "grown.php")
	body := append([]byte("<?php EVIL_MARKER_B;"), bytes.Repeat([]byte("/"), 2<<20)...)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, err = contentStillMatches("signature_match_realtime", path, info)
	if !errors.Is(err, errContentSnapshotTooLarge) {
		t.Fatalf("2 MiB flagged file above a 1 MiB ceiling was read: err = %v", err)
	}

	result := reverifyContentFinding(VerifyInput{
		Check:         "signature_match_realtime",
		Path:          path,
		ContentSHA256: "confirmed-finding-hash",
	})
	if result.Checked || result.Resolved {
		t.Fatalf("oversized confirmed finding was cleared: %+v", result)
	}
	if !strings.Contains(result.Detail, "read limit") {
		t.Fatalf("reverify detail = %q, want bounded-read failure", result.Detail)
	}
}
