package checks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// A YARA scan that could not complete (worker down, payload too large for one
// IPC frame, transport error) must NOT let the re-check auto-resolve a
// still-infected finding as a false positive. Before the fix the worker mapped
// such errors to zero matches, so a 12.6-16 MiB infected file was auto-cleared.
func TestContentReverifyYARAScanErrorFailsClosed(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	orig := contentYARAScanner
	contentYARAScanner = func() yara.Backend { return scanErrBackend{} }
	t.Cleanup(func() { contentYARAScanner = orig })

	p := filepath.Join(tmp, "infected.bin")
	if err := os.WriteFile(p, []byte("infected-but-unscannable"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash := FileContentSHA256(p)

	res := reverifyContentFinding(VerifyInput{Check: "yara_match_realtime", Path: p, ContentSHA256: hash})
	if res.Resolved {
		t.Fatalf("a YARA scan error must not auto-resolve the finding, got %+v", res)
	}
	if res.Checked {
		t.Errorf("scan error should leave Checked=false (inconclusive), got %+v", res)
	}
	if !strings.Contains(res.Detail, "scan error") {
		t.Errorf("detail should mention the scan error, got %q", res.Detail)
	}
}

func TestContentReverifyOversizeArchiveResolvesWithoutYARAScan(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	orig := contentYARAScanner
	contentYARAScanner = func() yara.Backend { return scanErrBackend{} }
	t.Cleanup(func() { contentYARAScanner = orig })

	archive := make([]byte, yaraipc.MaxScanBytes+1)
	copy(archive, []byte{'P', 'K', 0x03, 0x04})
	p := filepath.Join(tmp, "oversize.zip")
	if err := os.WriteFile(p, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := FileContentSHA256(p)
	if hash == "" {
		t.Fatal("oversize inline archive must remain within the reverify fingerprint limit")
	}

	res := reverifyContentFinding(VerifyInput{Check: "yara_match_realtime", Path: p, ContentSHA256: hash})
	if !res.Checked || !res.Resolved {
		t.Fatalf("unchanged archive must resolve before the backend rejects its size, got %+v", res)
	}
}

// scanErrBackend looks healthy (RuleCount>0) but its checked scan always
// fails, modelling an oversize payload or a crashed worker.
type scanErrBackend struct{}

func (scanErrBackend) ScanFile(string, int) []yara.Match { return nil }
func (scanErrBackend) ScanBytes([]byte) []yara.Match     { return nil }
func (scanErrBackend) ScanBytesChecked([]byte) ([]yara.Match, error) {
	return nil, errors.New("frame length exceeds cap")
}
func (scanErrBackend) Reload() error  { return nil }
func (scanErrBackend) RuleCount() int { return 5 }

// byteOnlyErrBackend fails byte scans with a transport error and fails the
// test if anything retries by path.
type byteOnlyErrBackend struct{ t *testing.T }

func (b byteOnlyErrBackend) ScanFile(path string, _ int) []yara.Match {
	b.t.Errorf("re-check reopened %s by path", path)
	return nil
}
func (b byteOnlyErrBackend) ScanFileChecked(path string, _ int) (yara.FileScanResult, error) {
	b.t.Errorf("re-check reopened %s by path", path)
	return yara.FileScanResult{}, errors.New("path scan")
}
func (byteOnlyErrBackend) ScanBytes([]byte) []yara.Match { return nil }
func (byteOnlyErrBackend) ScanBytesChecked([]byte) ([]yara.Match, error) {
	return nil, fmt.Errorf("worker: %w", yaraipc.ErrPayloadTooLarge)
}
func (byteOnlyErrBackend) Reload() error  { return nil }
func (byteOnlyErrBackend) RuleCount() int { return 5 }

// A failed re-check scan fails closed and is never retried by path.
func TestReverifyYARAByteScanErrorFailsClosedWithoutPathRetry(t *testing.T) {
	prev := contentYARAScanner
	contentYARAScanner = func() yara.Backend { return byteOnlyErrBackend{t: t} }
	t.Cleanup(func() { contentYARAScanner = prev })
	path := filepath.Join(t.TempDir(), "x.php")
	if err := os.WriteFile(path, []byte("<?php echo 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	matched, _, _, err := contentStillMatches("yara_match_scheduled", path, info)
	if err == nil || matched {
		t.Fatalf("failed scan = matched %v, err %v; want an error", matched, err)
	}
}
