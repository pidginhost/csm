package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func drainRealtimeRuleFinding(t *testing.T, d *Daemon) (alert.Finding, bool) {
	t.Helper()
	select {
	case f := <-d.alertCh:
		return f, true
	default:
		return alert.Finding{}, false
	}
}

// A mistyped rules directory or an empty rule sync used to leave the realtime
// scanners running against zero rules while the daemon looked healthy: every
// write was "scanned" and nothing could ever match. The coverage report turns
// that state into a finding.
func TestRealtimeRuleCoverageReportsEmptyEngines(t *testing.T) {
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = "/etc/csm/rules-typo"
	d := New(cfg, nil, nil, "")

	d.reportRealtimeRuleCoverage(0, 0, false)
	f, ok := drainRealtimeRuleFinding(t, d)
	if !ok {
		t.Fatal("no finding for a YAML engine with zero rules")
	}
	if f.Check != "realtime_rules_missing" || f.Severity != alert.High {
		t.Fatalf("finding = %s/%s, want realtime_rules_missing/High", f.Check, f.Severity)
	}
	if !strings.Contains(f.Message, "/etc/csm/rules-typo") {
		t.Fatalf("finding message %q does not name the rules directory", f.Message)
	}

	d.reportRealtimeRuleCoverage(114, 0, true)
	f, ok = drainRealtimeRuleFinding(t, d)
	if !ok {
		t.Fatal("no finding for an active YARA backend with zero rules")
	}
	if !strings.Contains(f.Message, "YARA") {
		t.Fatalf("finding message %q does not name the YARA engine", f.Message)
	}
}

// Engines that carry rules are silent, and a YARA backend that is not active
// is covered by its own unavailability findings rather than this one.
func TestRealtimeRuleCoverageStaysQuietWhenRulesLoaded(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")

	d.reportRealtimeRuleCoverage(114, 5, true)
	if f, ok := drainRealtimeRuleFinding(t, d); ok {
		t.Fatalf("unexpected finding %s with both engines loaded", f.Check)
	}
	d.reportRealtimeRuleCoverage(114, 0, false)
	if f, ok := drainRealtimeRuleFinding(t, d); ok {
		t.Fatalf("unexpected finding %s when the YARA backend is simply absent", f.Check)
	}
}
