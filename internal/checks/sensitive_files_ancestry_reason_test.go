package checks

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// The demote note has to name the evidence that produced it. Package-manager
// ancestry and control-panel maintenance are different claims, and an operator
// reading the finding cannot judge the demotion without knowing which one ran.
func TestRescoreSensitiveRecordsAncestryReason(t *testing.T) {
	oldPaths := pkgManagerLogs
	pkgManagerLogs = []string{filepath.Join(t.TempDir(), "missing.log")}
	t.Cleanup(func() { pkgManagerLogs = oldPaths })

	oldProbe := AncestryProvenance
	AncestryProvenance = func(uint32) string { return "ancestor is control panel maintenance" }
	t.Cleanup(func() { AncestryProvenance = oldProbe })

	out := rescoreSensitive(alert.Finding{Severity: alert.High}, "cron", nil, 4242, time.Now())
	if out.Severity != alert.Warning {
		t.Fatalf("severity = %v, want Warning", out.Severity)
	}
	if !strings.Contains(out.Details, "ancestor is control panel maintenance") {
		t.Fatalf("details = %q, want the probe's reason", out.Details)
	}
}

// An empty reason is the probe saying it proved nothing, and must leave the
// finding alone rather than reading as a successful demotion.
func TestRescoreSensitiveEmptyAncestryReasonDoesNotDemote(t *testing.T) {
	oldPaths := pkgManagerLogs
	pkgManagerLogs = []string{filepath.Join(t.TempDir(), "missing.log")}
	t.Cleanup(func() { pkgManagerLogs = oldPaths })

	oldProbe := AncestryProvenance
	AncestryProvenance = func(uint32) string { return "" }
	t.Cleanup(func() { AncestryProvenance = oldProbe })

	out := rescoreSensitive(alert.Finding{Severity: alert.High}, "cron", nil, 4242, time.Now())
	if out.Severity != alert.High {
		t.Fatalf("severity = %v, want High", out.Severity)
	}
}
