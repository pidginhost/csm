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

func (b *errCheckedBackend) ScanFile(string, int) []Match             { return nil }
func (b *errCheckedBackend) ScanBytes([]byte) []Match                 { return nil }
func (b *errCheckedBackend) ScanBytesChecked([]byte) ([]Match, error) { return nil, b.err }
func (b *errCheckedBackend) Reload() error                            { return nil }
func (b *errCheckedBackend) RuleCount() int                           { return 1 }
