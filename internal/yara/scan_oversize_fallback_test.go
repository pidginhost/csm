package yara

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/yaraipc"
)

// A payload larger than one IPC frame is a transport limit, not a property of
// the file, and the worker can already read the file itself. Callers that hold
// a path were still reporting the pre-check error, so an oversize attachment or
// a large finding under re-check could never be scanned at all -- the scheduled
// deep scan was the only caller that knew to retry by path.

type oversizeBackend struct {
	mockBackend
	pathCalls int
	pathRes   FileScanResult
	pathErr   error
}

func (b *oversizeBackend) ScanBytes([]byte) []Match { return nil }
func (b *oversizeBackend) ScanBytesChecked([]byte) ([]Match, error) {
	return nil, yaraipc.ErrPayloadTooLarge
}
func (b *oversizeBackend) ScanFile(string, int) []Match { return nil }
func (b *oversizeBackend) ScanFileChecked(string, int) (FileScanResult, error) {
	b.pathCalls++
	return b.pathRes, b.pathErr
}
func (b *oversizeBackend) Reload() error { return nil }

func TestScanContentOrPathCheckedFallsBackToPathWhenOversize(t *testing.T) {
	b := &oversizeBackend{pathRes: FileScanResult{
		Matches:       []Match{{RuleName: "webshell_example"}},
		ContentSHA256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
	}}

	matches, sha, err := ScanContentOrPathChecked(b, "/home/u/public_html/big.php", []byte("payload"), 16<<20)
	if err != nil {
		t.Fatalf("oversize payload was not retried by path: %v", err)
	}
	if b.pathCalls != 1 {
		t.Errorf("path scans = %d, want 1", b.pathCalls)
	}
	if len(matches) != 1 || matches[0].RuleName != "webshell_example" {
		t.Errorf("matches = %v, want the path scan's match", matches)
	}
	if sha != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Errorf("sha = %q, want the digest of the bytes actually scanned", sha)
	}
}

// A path scan that also fails must surface, never read as clean.
func TestScanContentOrPathCheckedSurfacesPathFailure(t *testing.T) {
	b := &oversizeBackend{pathErr: errors.New("worker exited")}

	if _, _, err := ScanContentOrPathChecked(b, "/home/u/big.php", []byte("payload"), 16<<20); err == nil {
		t.Fatal("a failed path retry must surface, not report clean")
	}
}

type inlineBackend struct {
	mockBackend
	pathCalls int
}

func (b *inlineBackend) ScanBytes([]byte) []Match { return nil }
func (b *inlineBackend) ScanBytesChecked([]byte) ([]Match, error) {
	return []Match{{RuleName: "inline_hit"}}, nil
}
func (b *inlineBackend) ScanFile(string, int) []Match { return nil }
func (b *inlineBackend) ScanFileChecked(string, int) (FileScanResult, error) {
	b.pathCalls++
	return FileScanResult{}, nil
}
func (b *inlineBackend) Reload() error { return nil }

// The fallback is for the transport limit alone: a payload that fits must not
// be read off disk a second time.
func TestScanContentOrPathCheckedDoesNotRereadWhenInlineSucceeds(t *testing.T) {
	b := &inlineBackend{}

	matches, sha, err := ScanContentOrPathChecked(b, "/home/u/small.php", []byte("payload"), 16<<20)
	if err != nil {
		t.Fatalf("inline scan failed: %v", err)
	}
	if b.pathCalls != 0 {
		t.Errorf("path scans = %d, want 0 when the inline scan succeeded", b.pathCalls)
	}
	if len(matches) != 1 {
		t.Errorf("matches = %v, want the inline match", matches)
	}
	if sha != "" {
		t.Errorf("sha = %q, want empty so the caller keeps its own snapshot digest", sha)
	}
}

// Any other scan failure is not a size problem and must not trigger a retry.
func TestScanContentOrPathCheckedDoesNotRetryOtherErrors(t *testing.T) {
	b := &errCheckedBackend{err: errors.New("worker exited")}

	if _, _, err := ScanContentOrPathChecked(b, "/home/u/x.php", []byte("payload"), 16<<20); err == nil {
		t.Fatal("a non-size scan error must surface")
	}
}
