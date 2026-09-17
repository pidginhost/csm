package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/control"
)

func TestRunFirewallActionsListsPendingWork(t *testing.T) {
	var got control.Request
	cleanup := fakeDaemon(t, func(req control.Request) control.Response {
		got = req
		return control.Response{OK: true, Result: json.RawMessage(`{"lines":["2026-03-04 05:06:08  unknown  block 203.0.113.5"]}`)}
	})
	out, err := runFirewallActions(nil)
	cleanup()
	if err != nil {
		t.Fatalf("runFirewallActions: %v", err)
	}
	if got.Cmd != control.CmdFirewallActions {
		t.Fatalf("cmd = %q", got.Cmd)
	}
	if !strings.Contains(out, "203.0.113.5") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunFirewallActionsResolveSendsOperatorDecision(t *testing.T) {
	var got control.Request
	cleanup := fakeDaemon(t, func(req control.Request) control.Response {
		got = req
		return control.Response{OK: true, Result: json.RawMessage(`{"message":"action stranded recorded as verified"}`)}
	})
	out, err := runFirewallActions([]string{"resolve", "stranded", "applied", "rule", "present"})
	cleanup()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Cmd != control.CmdFirewallActionResolve {
		t.Fatalf("cmd = %q", got.Cmd)
	}
	var args control.FirewallActionResolveArgs
	if err := json.Unmarshal(got.Args, &args); err != nil {
		t.Fatal(err)
	}
	if args.ID != "stranded" || args.Outcome != "applied" || args.Note != "rule present" {
		t.Fatalf("args = %#v", args)
	}
	if !strings.Contains(out, "verified") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunFirewallActionsRejectsUnusableArguments(t *testing.T) {
	called := false
	cleanup := fakeDaemon(t, func(control.Request) control.Response {
		called = true
		return control.Response{OK: true, Result: json.RawMessage(`{"lines":[]}`)}
	})
	for _, args := range [][]string{
		{"resolve"},
		{"resolve", "stranded"},
		{"resolve", "stranded", "maybe"},
		{"show", "stranded"},
		{"extra"},
	} {
		if _, err := runFirewallActions(args); err == nil {
			t.Errorf("runFirewallActions(%q) accepted unusable arguments", args)
		}
	}
	cleanup()
	if called {
		t.Fatal("unusable arguments reached the daemon")
	}
}
