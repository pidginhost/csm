package emailav

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	emime "github.com/pidginhost/cpanel-security-monitor/internal/mime"
)

// mockScanner implements Scanner for testing.
type mockScanner struct {
	name      string
	available bool
	verdict   Verdict
	scanErr   error
	delay     time.Duration
}

func (m *mockScanner) Name() string    { return m.name }
func (m *mockScanner) Available() bool { return m.available }
func (m *mockScanner) Scan(path string) (Verdict, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	return m.verdict, m.scanErr
}

func makeTempPart(t *testing.T, content string) emime.ExtractedPart {
	t.Helper()
	tmpFile := filepath.Join(t.TempDir(), "test-part")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return emime.ExtractedPart{
		Filename:    "test.exe",
		ContentType: "application/octet-stream",
		Size:        int64(len(content)),
		TempPath:    tmpFile,
	}
}

func TestOrchestratorBothClean(t *testing.T) {
	o := NewOrchestrator(
		[]Scanner{
			&mockScanner{name: "clamav", available: true, verdict: Verdict{Infected: false}},
			&mockScanner{name: "yara-x", available: true, verdict: Verdict{Infected: false}},
		},
		30*time.Second,
	)

	parts := []emime.ExtractedPart{makeTempPart(t, "clean content")}
	result := o.ScanParts("test-msg-id", parts, false)

	if result.Infected {
		t.Error("should be clean")
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0", len(result.Findings))
	}
	if len(result.EnginesUsed) != 2 {
		t.Errorf("EnginesUsed = %v, want 2 engines", result.EnginesUsed)
	}
}

func TestOrchestratorClamAVHit(t *testing.T) {
	o := NewOrchestrator(
		[]Scanner{
			&mockScanner{name: "clamav", available: true, verdict: Verdict{Infected: true, Signature: "Win.Trojan.Test", Severity: "critical"}},
			&mockScanner{name: "yara-x", available: true, verdict: Verdict{Infected: false}},
		},
		30*time.Second,
	)

	parts := []emime.ExtractedPart{makeTempPart(t, "malware")}
	result := o.ScanParts("test-msg-id", parts, false)

	if !result.Infected {
		t.Error("should be infected")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(result.Findings))
	}
	if result.Findings[0].Engine != "clamav" {
		t.Errorf("Engine = %q, want %q", result.Findings[0].Engine, "clamav")
	}
	if result.Findings[0].Signature != "Win.Trojan.Test" {
		t.Errorf("Signature = %q, want %q", result.Findings[0].Signature, "Win.Trojan.Test")
	}
}

func TestOrchestratorBothHit(t *testing.T) {
	o := NewOrchestrator(
		[]Scanner{
			&mockScanner{name: "clamav", available: true, verdict: Verdict{Infected: true, Signature: "ClamSig", Severity: "critical"}},
			&mockScanner{name: "yara-x", available: true, verdict: Verdict{Infected: true, Signature: "YaraSig", Severity: "high"}},
		},
		30*time.Second,
	)

	parts := []emime.ExtractedPart{makeTempPart(t, "multi-detect")}
	result := o.ScanParts("test-msg-id", parts, false)

	if !result.Infected {
		t.Error("should be infected")
	}
	if len(result.Findings) != 2 {
		t.Errorf("Findings = %d, want 2", len(result.Findings))
	}
}

func TestOrchestratorOneUnavailable(t *testing.T) {
	o := NewOrchestrator(
		[]Scanner{
			&mockScanner{name: "clamav", available: false},
			&mockScanner{name: "yara-x", available: true, verdict: Verdict{Infected: false}},
		},
		30*time.Second,
	)

	parts := []emime.ExtractedPart{makeTempPart(t, "content")}
	result := o.ScanParts("test-msg-id", parts, false)

	if result.Infected {
		t.Error("should be clean")
	}
	if len(result.EnginesUsed) != 1 {
		t.Errorf("EnginesUsed = %v, want 1", result.EnginesUsed)
	}
	if len(result.FailedEngines) != 1 || result.FailedEngines[0] != "clamav" {
		t.Errorf("FailedEngines = %v, want [clamav]", result.FailedEngines)
	}
}

func TestOrchestratorBothUnavailable(t *testing.T) {
	o := NewOrchestrator(
		[]Scanner{
			&mockScanner{name: "clamav", available: false},
			&mockScanner{name: "yara-x", available: false},
		},
		30*time.Second,
	)

	parts := []emime.ExtractedPart{makeTempPart(t, "content")}
	result := o.ScanParts("test-msg-id", parts, false)

	if result.Infected {
		t.Error("fail-open: should NOT be infected when both engines unavailable")
	}
	if len(result.FailedEngines) != 2 {
		t.Errorf("FailedEngines = %v, want 2", result.FailedEngines)
	}
}

func TestOrchestratorTimeout(t *testing.T) {
	o := NewOrchestrator(
		[]Scanner{
			&mockScanner{name: "clamav", available: true, delay: 5 * time.Second},
			&mockScanner{name: "yara-x", available: true, verdict: Verdict{Infected: false}},
		},
		100*time.Millisecond, // very short timeout
	)

	parts := []emime.ExtractedPart{makeTempPart(t, "content")}
	result := o.ScanParts("test-msg-id", parts, false)

	// fail-open: timed-out engine should not block result
	if result.Infected {
		t.Error("fail-open: should not be infected on timeout")
	}
}

func TestOrchestratorScanError(t *testing.T) {
	o := NewOrchestrator(
		[]Scanner{
			&mockScanner{name: "clamav", available: true, scanErr: fmt.Errorf("socket broken")},
			&mockScanner{name: "yara-x", available: true, verdict: Verdict{Infected: false}},
		},
		30*time.Second,
	)

	parts := []emime.ExtractedPart{makeTempPart(t, "content")}
	result := o.ScanParts("test-msg-id", parts, false)

	if result.Infected {
		t.Error("fail-open: scan error should not mark as infected")
	}
}
