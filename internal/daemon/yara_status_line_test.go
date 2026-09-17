package daemon

import (
	"strings"
	"testing"
)

// A worker that compiled no rules scans every buffer against nothing. Calling
// that "active" is how a host ran for hours reporting a healthy scanner while
// matching nothing at all -- the startup line said active, and a full account
// scan then completed with no findings, which reads as clean rather than as
// blind.
func TestYaraWorkerStatusLineZeroRules(t *testing.T) {
	line := yaraWorkerStatusLine(0, 4242)

	if strings.Contains(strings.ToLower(line), "active") {
		t.Errorf("a zero-rule worker is described as active: %q", line)
	}
	if !strings.Contains(line, "0 rule") {
		t.Errorf("line does not state the rule count: %q", line)
	}
	// The operator needs to know what it means, not just the number.
	if !strings.Contains(strings.ToLower(line), "scanning nothing") {
		t.Errorf("line does not say what a zero-rule worker means: %q", line)
	}
	if !strings.Contains(line, "4242") {
		t.Errorf("line does not carry the child pid: %q", line)
	}
}

// The healthy case must still read as healthy and keep its detail.
func TestYaraWorkerStatusLineWithRules(t *testing.T) {
	line := yaraWorkerStatusLine(162, 4242)

	if !strings.Contains(line, "active") {
		t.Errorf("a loaded worker is not described as active: %q", line)
	}
	for _, want := range []string{"162", "4242"} {
		if !strings.Contains(line, want) {
			t.Errorf("line missing %q: %q", want, line)
		}
	}
	if strings.Contains(strings.ToLower(line), "scanning nothing") {
		t.Errorf("healthy worker described as scanning nothing: %q", line)
	}
}
