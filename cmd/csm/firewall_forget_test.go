package main

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/control"
)

// The operator has to be able to tell "the stale score is gone" from "there
// was no record, so the alert you are chasing comes from somewhere else".
// Printing the same line for both hides the second case entirely.
func TestThreatForgetOutputDistinguishesFoundFromMissing(t *testing.T) {
	cleared := threatForgetOutput(control.ThreatForgetResult{
		IP: "198.51.100.23", Found: true, Score: 90, Events: 421,
		Message: "Cleared local threat record for 198.51.100.23 (was score 90/100, 421 attack events); block, allow and whitelist entries are unchanged",
	})
	if !strings.Contains(cleared, "90") || !strings.Contains(cleared, "421") {
		t.Errorf("cleared output does not report what was removed: %q", cleared)
	}

	missing := threatForgetOutput(control.ThreatForgetResult{
		IP: "203.0.113.99", Found: false,
		Message: "No local threat record for 203.0.113.99; nothing cleared",
	})
	if missing == cleared {
		t.Fatal("identical output for cleared and missing records")
	}
	if !strings.Contains(strings.ToLower(missing), "nothing cleared") {
		t.Errorf("missing-record output does not say nothing was cleared: %q", missing)
	}
}

// A daemon on an older build answers an unknown command with an error
// rather than a ThreatForgetResult. Falling back to a bare success line
// would tell the operator the record was cleared when it was not.
func TestThreatForgetOutputRejectsEmptyMessage(t *testing.T) {
	got := threatForgetOutput(control.ThreatForgetResult{IP: "198.51.100.23", Found: true, Score: 90, Events: 421})
	if got == "" {
		t.Fatal("empty output for a result with no message")
	}
	if !strings.Contains(got, "198.51.100.23") {
		t.Errorf("fallback output does not identify the address: %q", got)
	}
}

// `csm firewall deny --help` used to print "Invalid IP address: --help".
// forget takes an IP in the same position and must not reintroduce it.
func TestFirewallForgetTreatsHelpAsHelp(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "help"} {
		if !isHelpRequest([]string{arg}) {
			t.Errorf("isHelpRequest(%q) = false", arg)
		}
	}
	if isHelpRequest([]string{"198.51.100.23"}) {
		t.Error("an IP was treated as a help request")
	}
}
