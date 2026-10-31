//go:build !yara

package yara

import (
	"bytes"
	"errors"
	"testing"
)

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

func TestInitWithoutYara(t *testing.T) {
	s := Init("/nonexistent")
	if s != nil {
		t.Error("Init without YARA should return nil")
	}
}

func TestGlobalWithoutInit(t *testing.T) {
	if g := Global(); g != nil {
		t.Error("Global without Init should return nil")
	}
}

func TestRulesStubReportsNoEngine(t *testing.T) {
	if rules, err := CompileSources([]Source{{Name: "test.yar", Text: []byte("rule test { condition: true }")}}); rules != nil || !errors.Is(err, ErrNoEngine) {
		t.Fatalf("CompileSources = %v, %v; want nil, ErrNoEngine", rules, err)
	}
	input := bytes.NewBufferString("compiled rules")
	if rules, err := LoadRules(input); rules != nil || !errors.Is(err, ErrNoEngine) {
		t.Fatalf("LoadRules = %v, %v; want nil, ErrNoEngine", rules, err)
	}
	if input.String() != "compiled rules" {
		t.Fatal("LoadRules consumed input without an engine")
	}
	rules := &Rules{}
	var output bytes.Buffer
	if n, err := rules.WriteTo(&output); n != 0 || !errors.Is(err, ErrNoEngine) || output.Len() != 0 {
		t.Fatalf("WriteTo = %d, %v, %d output bytes; want 0, ErrNoEngine, no output", n, err, output.Len())
	}
	if matches, err := rules.Scan([]byte("probe")); matches != nil || !errors.Is(err, ErrNoEngine) {
		t.Fatalf("Scan = %v, %v; want nil, ErrNoEngine", matches, err)
	}
	if rules.Count() != 0 {
		t.Fatal("rules without an engine must have zero count")
	}
}
