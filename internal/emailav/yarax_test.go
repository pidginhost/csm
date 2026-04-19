//go:build yara

package emailav

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/yara"
)

// fakeBackend is a yara.Backend stand-in. The adapter under test is
// thin: all the YARA-X semantics live in internal/yara and are
// exercised by scanner_meta_test.go against real compiled rules.
// These tests therefore cover the adapter's own policy — severity
// default, file-read error handling, unavailable-backend handling —
// without re-verifying the YARA engine itself.
type fakeBackend struct {
	matches   []yara.Match
	ruleCount int
	scanned   [][]byte
}

func (f *fakeBackend) ScanFile(string, int) []yara.Match { return nil }
func (f *fakeBackend) ScanBytes(data []byte) []yara.Match {
	f.scanned = append(f.scanned, append([]byte(nil), data...))
	return f.matches
}
func (f *fakeBackend) Reload() error  { return nil }
func (f *fakeBackend) RuleCount() int { return f.ruleCount }

func TestYaraXScannerNameAndAvailability(t *testing.T) {
	tests := []struct {
		name      string
		backend   yara.Backend
		wantName  string
		wantAvail bool
	}{
		{"nil backend", nil, "yara-x", false},
		{"zero rules", &fakeBackend{ruleCount: 0}, "yara-x", false},
		{"with rules", &fakeBackend{ruleCount: 42}, "yara-x", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewYaraXScanner(tt.backend)
			if got := s.Name(); got != tt.wantName {
				t.Errorf("Name() = %q, want %q", got, tt.wantName)
			}
			if got := s.Available(); got != tt.wantAvail {
				t.Errorf("Available() = %v, want %v", got, tt.wantAvail)
			}
		})
	}
}

func TestYaraXScannerScanCleanFileReturnsNoMatch(t *testing.T) {
	b := &fakeBackend{ruleCount: 1, matches: nil}
	s := NewYaraXScanner(b)
	tmp := filepath.Join(t.TempDir(), "clean.bin")
	if err := os.WriteFile(tmp, []byte("benign content"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := s.Scan(tmp)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v.Infected {
		t.Errorf("Infected = true for clean file, want false")
	}
	if len(b.scanned) != 1 {
		t.Errorf("backend ScanBytes calls = %d, want 1", len(b.scanned))
	}
}

func TestYaraXScannerReadsSeverityFromMetadata(t *testing.T) {
	b := &fakeBackend{
		ruleCount: 1,
		matches: []yara.Match{{
			RuleName: "webshell_p0wny",
			Meta:     map[string]string{"severity": "critical", "description": "ignored here"},
		}},
	}
	s := NewYaraXScanner(b)
	tmp := filepath.Join(t.TempDir(), "sus.bin")
	if err := os.WriteFile(tmp, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := s.Scan(tmp)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !v.Infected {
		t.Error("Infected = false, want true")
	}
	if v.Signature != "webshell_p0wny" {
		t.Errorf("Signature = %q, want %q", v.Signature, "webshell_p0wny")
	}
	if v.Severity != "critical" {
		t.Errorf("Severity = %q, want %q (from metadata)", v.Severity, "critical")
	}
}

func TestYaraXScannerDefaultsSeverityWhenMetadataAbsent(t *testing.T) {
	// Rule authors sometimes ship rules without a severity key. The
	// adapter's fallback must be "high" so an unlabelled match never
	// disappears into the "warning" bucket that some alert routes
	// suppress. Kept as an explicit assertion so a future refactor
	// that changes the default surfaces here instead of in prod.
	b := &fakeBackend{
		ruleCount: 1,
		matches:   []yara.Match{{RuleName: "rule_without_severity"}},
	}
	s := NewYaraXScanner(b)
	tmp := filepath.Join(t.TempDir(), "match.bin")
	if err := os.WriteFile(tmp, []byte("anything"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := s.Scan(tmp)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v.Severity != defaultSeverity {
		t.Errorf("Severity = %q, want %q (default when metadata absent)", v.Severity, defaultSeverity)
	}
}

func TestYaraXScannerEmptySeverityStringFallsBackToDefault(t *testing.T) {
	// An explicit empty "severity" string is treated the same as missing
	// — defensively, since a rule author writing severity="" almost
	// certainly did not mean "this match has no priority at all".
	b := &fakeBackend{
		ruleCount: 1,
		matches: []yara.Match{{
			RuleName: "test_rule",
			Meta:     map[string]string{"severity": ""},
		}},
	}
	s := NewYaraXScanner(b)
	tmp := filepath.Join(t.TempDir(), "match.bin")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := s.Scan(tmp)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v.Severity != defaultSeverity {
		t.Errorf("Severity = %q, want %q", v.Severity, defaultSeverity)
	}
}

func TestYaraXScannerScanErrorsOnUnreadableFile(t *testing.T) {
	s := NewYaraXScanner(&fakeBackend{ruleCount: 1})
	_, err := s.Scan(filepath.Join(t.TempDir(), "does-not-exist.bin"))
	if err == nil {
		t.Fatal("expected error reading nonexistent file")
	}
}

func TestYaraXScannerNilBackendReturnsError(t *testing.T) {
	s := NewYaraXScanner(nil)
	tmp := filepath.Join(t.TempDir(), "x.bin")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Scan(tmp); err == nil {
		t.Fatal("expected error when backend is nil")
	}
}
