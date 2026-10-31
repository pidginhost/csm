package checks

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/yara"
)

type reverifySnapshotBackend struct {
	t       *testing.T
	wantSHA string
	matches []yara.Match
	err     error
	calls   int
}

func (b *reverifySnapshotBackend) ScanBytes([]byte) []yara.Match {
	b.t.Fatal("re-verification used an unchecked scan")
	return nil
}

func (b *reverifySnapshotBackend) ScanBytesChecked(data []byte) ([]yara.Match, error) {
	b.calls++
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != b.wantSHA {
		b.t.Fatalf("scanned digest = %s, want %s", got, b.wantSHA)
	}
	return b.matches, b.err
}

func (*reverifySnapshotBackend) RuleCount() int { return 1 }
func (*reverifySnapshotBackend) Reload() error  { return nil }

// Large findings already carry a digest from the detection snapshot. A
// successful byte re-check must compare the entire scanned snapshot with it.
func TestReverifyYARALargeSnapshot(t *testing.T) {
	prevConfig := config.Active()
	cfg := &config.Config{}
	cfg.Thresholds.FullScanMaxFileMB = 32
	config.SetActive(cfg)
	t.Cleanup(func() { config.SetActive(prevConfig) })

	for _, check := range []string{"yara_match_realtime", "yara_match_scheduled"} {
		t.Run(check, func(t *testing.T) {
			for _, outcome := range []string{"unchanged", "changed", "matched", "scan_error"} {
				t.Run(outcome, func(t *testing.T) {
					root := t.TempDir()
					withQuarantineAllowedRoots(t, root)
					data := bytes.Repeat([]byte(" "), contentFingerprintMaxBytes+1)
					copy(data, "<?php /* benign content */")
					detectedSHA := fmt.Sprintf("%x", sha256.Sum256(data))
					if outcome == "changed" {
						data[len(data)-1] = '\n'
					}
					path := filepath.Join(root, "large.php")
					if err := os.WriteFile(path, data, 0o600); err != nil {
						t.Fatal(err)
					}
					backend := &reverifySnapshotBackend{t: t, wantSHA: fmt.Sprintf("%x", sha256.Sum256(data))}
					if outcome == "matched" {
						backend.matches = []yara.Match{{RuleName: "test_hit"}}
					}
					if outcome == "scan_error" {
						backend.err = errors.New("worker unavailable")
					}
					prev := contentYARAScanner
					contentYARAScanner = func() yara.Backend { return backend }
					t.Cleanup(func() { contentYARAScanner = prev })

					got := reverifyContentFinding(VerifyInput{Check: check, Path: path, ContentSHA256: detectedSHA})
					if backend.calls != 1 {
						t.Fatalf("byte scans = %d, want exactly one: %+v", backend.calls, got)
					}
					if got.Checked != (outcome != "scan_error") || got.Resolved != (outcome == "unchanged") || got.Demote {
						t.Fatalf("re-verification for %s = %+v", outcome, got)
					}
				})
			}
		})
	}
}
