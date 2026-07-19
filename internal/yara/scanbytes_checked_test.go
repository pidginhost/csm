package yara

import (
	"errors"
	"testing"
)

// A backend that implements CheckedScanner must have its scan error surfaced,
// so callers can distinguish "scan failed" from "file is clean".
func TestScanBytesCheckedSurfacesCheckedScannerError(t *testing.T) {
	eb := &errCheckedBackend{err: errors.New("frame length exceeds cap")}
	_, err := ScanBytesChecked(eb, []byte("x"))
	if err == nil {
		t.Fatal("ScanBytesChecked must surface a CheckedScanner error")
	}
}

func TestScanBytesCheckedNilBackendErrors(t *testing.T) {
	_, err := ScanBytesChecked(nil, []byte("x"))
	if err == nil {
		t.Fatal("nil backend must return an error, not panic or report clean")
	}
}

func TestScanFileCheckedSurfacesCheckedScannerError(t *testing.T) {
	eb := &errCheckedBackend{err: errors.New("worker exited")}
	_, err := ScanFileChecked(eb, "/tmp/large.php", 16<<20)
	if err == nil {
		t.Fatal("ScanFileChecked must surface a CheckedFileScanner error")
	}
}

func TestScanFileCheckedNilBackendErrors(t *testing.T) {
	_, err := ScanFileChecked(nil, "/tmp/large.php", 16<<20)
	if err == nil {
		t.Fatal("nil backend must return an error, not panic or report clean")
	}
}

func TestScanFileCheckedRejectsPlainBackend(t *testing.T) {
	_, err := ScanFileChecked(&mockBackend{}, "/tmp/large.php", 16<<20)
	if err == nil {
		t.Fatal("backend without checked path scans must not report a clean result")
	}
}

func TestScanFileCheckedRejectsMissingContentHash(t *testing.T) {
	_, err := ScanFileChecked(&emptyFileResultBackend{}, "/tmp/large.php", 16<<20)
	if err == nil {
		t.Fatal("checked path scan without a content hash must not report clean")
	}
}

// A backend that predates the capability falls back to the error-free
// ScanBytes and returns its matches with a nil error.
func TestScanBytesCheckedFallsBackForPlainBackend(t *testing.T) {
	m, err := ScanBytesChecked(&mockBackend{}, []byte("x"))
	if err != nil {
		t.Fatalf("plain backend fallback must not error: %v", err)
	}
	if len(m) != 1 {
		t.Errorf("fallback should return ScanBytes matches, got %d", len(m))
	}
}

type errCheckedBackend struct{ err error }

type emptyFileResultBackend struct{ mockBackend }

func (b *emptyFileResultBackend) ScanFileChecked(string, int) (FileScanResult, error) {
	return FileScanResult{}, nil
}

func (b *errCheckedBackend) ScanFile(string, int) []Match { return nil }
func (b *errCheckedBackend) ScanFileChecked(string, int) (FileScanResult, error) {
	return FileScanResult{}, b.err
}
func (b *errCheckedBackend) ScanBytes([]byte) []Match                 { return nil }
func (b *errCheckedBackend) ScanBytesChecked([]byte) ([]Match, error) { return nil, b.err }
func (b *errCheckedBackend) Reload() error                            { return nil }
func (b *errCheckedBackend) RuleCount() int                           { return 1 }
