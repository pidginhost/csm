package checks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/yara"
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
