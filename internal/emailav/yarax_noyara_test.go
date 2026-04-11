//go:build !yara

package emailav

import "testing"

// These tests exercise the stub implementation compiled when the `yara`
// build tag is not set (the default). The real YaraXScanner lives in
// yarax.go behind //go:build yara and is covered by yarax_test.go.

func TestYaraXStubNewScannerReturnsNonNil(t *testing.T) {
	s := NewYaraXScanner(nil)
	if s == nil {
		t.Fatal("NewYaraXScanner should never return nil")
	}
}

func TestYaraXStubNameIdentifiesItself(t *testing.T) {
	s := NewYaraXScanner(nil)
	if name := s.Name(); name != "yara-x" {
		t.Errorf("Name() = %q, want yara-x", name)
	}
}

func TestYaraXStubAvailableIsFalse(t *testing.T) {
	s := NewYaraXScanner(nil)
	if s.Available() {
		t.Error("stub YaraXScanner must report Available() == false")
	}
}

func TestYaraXStubScanReturnsCleanVerdict(t *testing.T) {
	s := NewYaraXScanner(nil)
	v, err := s.Scan("/any/path.eml")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v.Infected {
		t.Error("stub Scan should return a clean verdict (Infected=false)")
	}
	if v.Signature != "" {
		t.Errorf("stub Scan should return empty Signature, got %q", v.Signature)
	}
}
