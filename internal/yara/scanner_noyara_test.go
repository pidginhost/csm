//go:build !yara

package yara

import "testing"

func TestNewScannerReturnsNil(t *testing.T) {
	s, err := NewScanner("/nonexistent")
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if s != nil {
		t.Error("scanner should be nil without yara")
	}
}

func TestScannerStubMethods(t *testing.T) {
	s := &Scanner{}
	if err := s.Reload(); err != nil {
		t.Errorf("Reload: %v", err)
	}
	if got := s.ScanBytes([]byte("test")); got != nil {
		t.Errorf("ScanBytes = %v", got)
	}
	if got := s.ScanFile("/tmp/test", 0); got != nil {
		t.Errorf("ScanFile = %v", got)
	}
	if got := s.RuleCount(); got != 0 {
		t.Errorf("RuleCount = %d", got)
	}
	if got := s.GlobalRules(); got != nil {
		t.Errorf("GlobalRules = %v", got)
	}
}

func TestAvailableFalse(t *testing.T) {
	if Available() {
		t.Error("Available should be false without yara")
	}
}

func TestTestCompileNoop(t *testing.T) {
	if err := TestCompile("rule test { condition: true }"); err != nil {
		t.Errorf("TestCompile: %v", err)
	}
}
