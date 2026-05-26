package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestDynDNSUnresolvableFindingIsWarning(t *testing.T) {
	f := dynDNSUnresolvableFinding("panel.example.com")
	if f.Check != "infra_ips_unresolvable" {
		t.Fatalf("check = %q, want infra_ips_unresolvable", f.Check)
	}
	if f.Severity != alert.Warning {
		t.Fatalf("severity = %v, want Warning", f.Severity)
	}
	if f.Timestamp.IsZero() {
		t.Fatal("timestamp was not set")
	}
	if !strings.Contains(f.Message, "panel.example.com") {
		t.Fatalf("message does not include host: %q", f.Message)
	}
	if !strings.Contains(f.Details, "infra_ips") || !strings.Contains(f.Details, "firewall.dyndns_hosts") {
		t.Fatalf("details should point at the configured host list, got %q", f.Details)
	}
}
