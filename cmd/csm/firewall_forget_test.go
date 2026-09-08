package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/control"
)

func TestRunThreatForgetRejectsExtraArguments(t *testing.T) {
	called := false
	cleanup := fakeDaemon(t, func(req control.Request) control.Response {
		called = true
		return control.Response{OK: true, Result: json.RawMessage(`{"ip":"198.51.100.23","found":true}`)}
	})
	for _, args := range [][]string{
		nil,
		{"not-an-ip"},
		{"198.51.100.23", "--dry-run"},
		{"198.51.100.23", "203.0.113.23"},
	} {
		if _, err := runThreatForget(args); err == nil {
			t.Errorf("runThreatForget(%q) accepted invalid arguments", args)
		}
	}
	cleanup()
	if called {
		t.Fatal("invalid arguments sent a destructive request")
	}
}

func TestRunThreatForgetSendsCommandAndReportsDaemonErrors(t *testing.T) {
	for _, fail := range []bool{false, true} {
		cleanup := fakeDaemon(t, func(req control.Request) control.Response {
			if req.Cmd != control.CmdThreatForget || string(req.Args) != `{"ip":"198.51.100.23"}` {
				t.Errorf("unexpected request: %+v", req)
			}
			if fail {
				return control.Response{Error: "attack database unavailable"}
			}
			return control.Response{OK: true, Result: json.RawMessage(`{"ip":"198.51.100.23","found":true,"message":"cleared test record"}`)}
		})
		out, err := runThreatForget([]string{"198.51.100.23"})
		cleanup()
		if fail {
			if err == nil || !strings.Contains(err.Error(), "attack database unavailable") || out != "" {
				t.Fatalf("daemon error hidden: output=%q, err=%v", out, err)
			}
		} else if err != nil || out != "cleared test record" {
			t.Fatalf("success reply: output=%q, err=%v", out, err)
		}
	}
}

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

// A valid result without wording still needs to identify the address.
func TestThreatForgetOutputFallsBackWithoutMessage(t *testing.T) {
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
