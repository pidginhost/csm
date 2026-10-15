package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/actionlog"
)

func TestActionShowRecords(t *testing.T) {
	for _, tc := range []struct {
		ref    string
		result actionlog.Result
		err    string
	}{
		{"cand_11111111111111111111111111111111", "read", ""},
		{"act_11111111111111111111111111111111", "read", ""},
		{"ip:192.0.2.1", actionlog.Failed, "fixture lookup failed"},
		{"", actionlog.Failed, "fixture malformed arguments"},
	} {
		a := NewAnonymizer(testSalt())
		r := actionlog.Record{V: 1, Timestamp: recordTS, Op: "respond.block_ip", Action: "show",
			Actor: actionlog.CLI, ActorDetail: "csm action show", Target: tc.ref, Result: tc.result, Error: tc.err}
		out, err := a.Action(r)
		if err != nil {
			t.Fatalf("show %q: %v", tc.ref, err)
		}
		if verifyErr := a.VerifyAction(out); verifyErr != nil {
			t.Fatalf("verify show %q: %v", tc.ref, verifyErr)
		}
		kind, target := "empty", ""
		if tc.ref != "" {
			kind, target = "opaque", a.ID(idTarget, tc.ref)
		}
		if out.TargetKind != kind || out.Target != target || out.Result != string(tc.result) || out.HasError != (tc.err != "") || out.ActionID != "" || out.ActionVersion != 0 {
			t.Fatalf("show transformed as enforcement: %+v", out)
		}
		raw, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		if (tc.ref != "" && strings.Contains(string(raw), tc.ref)) || strings.Contains(string(raw), "fixture") || strings.Contains(string(raw), "csm action show") {
			t.Fatalf("show leaked free text: %s", raw)
		}
	}
}

func TestActionShowRecordsRejectOtherClaims(t *testing.T) {
	base := actionlog.Record{V: 1, Timestamp: recordTS, Op: "respond.block_ip", Action: "show",
		Actor: actionlog.CLI, ActorDetail: "csm action show", Target: "cand_11111111111111111111111111111111", Result: "read"}
	for _, change := range []func(*actionlog.Record){
		func(r *actionlog.Record) { r.Op = "operate.manual_firewall" },
		func(r *actionlog.Record) { r.Actor = actionlog.Daemon },
		func(r *actionlog.Record) { r.Result = actionlog.Applied },
		func(r *actionlog.Record) { r.ActionID = "act_11111111111111111111111111111111" },
		func(r *actionlog.Record) { r.ActionVersion = 1 },
		func(r *actionlog.Record) { r.Count = 1 },
		func(r *actionlog.Record) { r.Target = "" },
	} {
		r := base
		change(&r)
		if _, err := validateAction(r); err == nil {
			t.Fatalf("invalid show accepted: %+v", r)
		}
	}
	a := NewAnonymizer(testSalt())
	out, err := a.Action(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*anonAction){
		func(o *anonAction) { o.Op = "operate.manual_firewall" },
		func(o *anonAction) { o.Actor = string(actionlog.Daemon) },
		func(o *anonAction) { o.Result = string(actionlog.Applied) },
		func(o *anonAction) { o.ActionID = a.ID(idAction, "act_11111111111111111111111111111111") },
		func(o *anonAction) { o.ActionVersion = 1 },
		func(o *anonAction) { o.Count = 1 },
		func(o *anonAction) { o.Target = base.Target },
	} {
		forged := out
		change(&forged)
		if verifyErr := a.VerifyAction(forged); verifyErr == nil {
			t.Fatalf("forged show verified: %+v", forged)
		}
	}
}
