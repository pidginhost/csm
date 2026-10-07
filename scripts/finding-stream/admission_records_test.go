package main

import (
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/checks"
)

// admissionRow is one admission audit row as the ledger owner writes it.
func admissionRow(action, target string, result actionlog.Result) actionlog.Record {
	return actionlog.Record{
		V: 1, Timestamp: recordTS, Op: "respond.block_ip", Action: action, Actor: actionlog.Daemon,
		FindingID: "0123456789abcdef", ActionID: "act_0123456789abcdef0123456789abcdef", ActionVersion: 2,
		Target: target, Reason: "general lane, expires 2026-09-08T11:00:00Z", Result: result,
	}
}

// summaryRow is one hourly admission summary.
func summaryRow(result actionlog.Result, refusal string) actionlog.Record {
	return actionlog.Record{
		V: 1, Timestamp: recordTS, Op: "respond.block_ip", Action: "block_ip", Actor: actionlog.Daemon,
		ActorDetail: "challenge_timeout", Reason: "pam_bruteforce", Result: result, Error: refusal, Count: 3,
	}
}

// The admission vocabulary is the ledger's own, so a new kind, entry,
// lane or reason is reviewed here before it can leave the host.
func TestAdmissionVocabulariesMatchTheLedger(t *testing.T) {
	wantChecks := append(checks.AllCheckNames(), "unknown")
	slices.Sort(wantChecks)
	if got := sortedKeys(admissionChecks); !slices.Equal(got, wantChecks) {
		t.Fatalf("checks = %v, want %v", got, wantChecks)
	}
	var kinds, entries, reasons, lanes []string
	for k := admission.Kind(1); k.Valid(); k++ {
		kinds = append(kinds, k.String())
	}
	for e := admission.Entry(1); e.Valid(); e++ {
		entries = append(entries, e.String())
	}
	for r := admission.Reason(1); r.Valid(); r++ {
		reasons = append(reasons, r.String())
	}
	for l := admission.Lane(1); l.Valid(); l++ {
		lanes = append(lanes, "admission_"+l.String())
	}
	for _, tc := range []struct {
		name string
		got  map[string]bool
		want []string
	}{
		{"kinds", admissionKinds, kinds}, {"entries", admissionEntries, entries}, {"reasons", admissionRefusals, reasons},
		{"attempt results", admissionAttemptResults, []string{"applied", "dry_run", "executing", "failed", "narrowed", "observe", "reserved", "unknown"}},
		{"decisions", admissionDecisions, []string{"coalesced", "observe", "queued", "refused"}},
	} {
		slices.Sort(tc.want)
		if got := sortedKeys(tc.got); !slices.Equal(got, tc.want) {
			t.Errorf("%s = %v, want %v", tc.name, got, tc.want)
		}
	}
	for _, lane := range lanes {
		if !reasonKinds[lane] {
			t.Errorf("lane reason kind %q is not accepted", lane)
		}
	}
}

// An admission audit row keeps its kind and step, and its typed target maps
// to the pseudonym the legacy row for the same address gets, so the two
// streams join.
func TestAdmissionAuditRowsAreTyped(t *testing.T) {
	a := NewAnonymizer(testSalt())
	for _, tc := range []struct {
		action, target, kind string
		bits, port           int
		proto, addr          string
	}{
		{"block_ip", "ip:203.0.113.9", "ip", 0, 0, "", "203.0.113.9"},
		{"challenge", "ip:2001:db8::9", "ip", 0, 0, "", "2001:db8::9"},
		{"promote", "ip:203.0.113.9", "ip", 0, 0, "", "203.0.113.9"},
		{"block_subnet", "net:203.0.113.0/24", "cidr", 24, 0, "", "203.0.113.0"},
		{"block_service", "svc:203.0.113.9/tcp/22", "endpoint", 0, 22, "tcp", "203.0.113.9"},
	} {
		out, err := a.Action(admissionRow(tc.action, tc.target, "reserved"))
		if err != nil {
			t.Fatalf("%s %s: %v", tc.action, tc.target, err)
		}
		if out.Action != tc.action || out.TargetKind != tc.kind || out.TargetPrefix != tc.bits || out.TargetPort != tc.port ||
			out.TargetProto != tc.proto || out.Target != a.mapAddr(parseAddr(t, tc.addr)) || out.ReasonKind != "admission_general" {
			t.Errorf("%s %s -> %+v", tc.action, tc.target, out)
		}
		if err = a.VerifyAction(out); err != nil {
			t.Errorf("%s %s: verifier refused %+v: %v", tc.action, tc.target, out, err)
		}
	}
	steps := map[string]bool{}
	for result := range admissionAttemptResults {
		out, err := a.Action(admissionRow("block_ip", "ip:203.0.113.9", actionlog.Result(result)))
		if err != nil || a.VerifyAction(out) != nil {
			t.Fatalf("step %q: %+v %v", result, out, err)
		}
		steps[out.Result] = true
	}
	if len(steps) != len(admissionAttemptResults) {
		t.Fatalf("steps collapsed: %v", steps)
	}
	for lane, kind := range map[string]string{"direct": "admission_direct", "corroborated": "admission_corroborated"} {
		r := admissionRow("block_ip", "ip:203.0.113.9", "observe")
		r.Reason = lane + " lane, expires 2026-09-08T11:00:00Z"
		if out, err := a.Action(r); err != nil || out.ReasonKind != kind {
			t.Errorf("%s lane -> %+v %v", lane, out, err)
		}
	}
}

func TestAdmissionAuditRowRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		rec  actionlog.Record
		want error
	}{
		"legacy action":         {admissionRow("block", "ip:203.0.113.9", "reserved"), errUnknownAction},
		"admission kind, raw":   {admissionRow("block_ip", "203.0.113.9", actionlog.Applied), errUnknownAction},
		"queue decision":        {admissionRow("block_ip", "ip:203.0.113.9", "queued"), errUnknownResult},
		"legacy result":         {admissionRow("block_ip", "ip:203.0.113.9", actionlog.Refused), errUnknownResult},
		"name as address":       {admissionRow("block_ip", "ip:alice", "reserved"), errTargetAddress},
		"whole family":          {admissionRow("block_subnet", "net:0.0.0.0/0", "reserved"), errTargetAddress},
		"unmasked network":      {admissionRow("block_subnet", "net:203.0.113.9/24", "reserved"), errTargetAddress},
		"service without proto": {admissionRow("block_service", "svc:203.0.113.9/22", "reserved"), errTargetAddress},
		"kind and target":       {admissionRow("block_ip", "net:203.0.113.0/24", "reserved"), errTargetAddress},
		"mapped address":        {admissionRow("block_ip", "ip:::ffff:203.0.113.9", "reserved"), errTargetAddress},
		"upper-case address":    {admissionRow("block_ip", "ip:2001:DB8::9", "reserved"), errTargetAddress},
		"no action id":          {withoutAdmissionLink("action_id"), errAdmissionStep},
		"no version":            {withoutAdmissionLink("version"), errAdmissionStep},
		"no finding id":         {withoutAdmissionLink("finding_id"), errAdmissionStep},
		"no lane":               {withReason(admissionRow("block_ip", "ip:203.0.113.9", "reserved"), "CSM auto-block: brute force"), errAdmissionStep},
	} {
		if _, err := NewAnonymizer(testSalt()).Action(tc.rec); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
	legacy := fullRecord()
	for _, result := range []actionlog.Result{"reserved", "executing", "observe", "narrowed", "queued", "coalesced"} {
		legacy.Result = result
		if _, err := NewAnonymizer(testSalt()).Action(legacy); !errors.Is(err, errUnknownResult) {
			t.Errorf("legacy row with %q: %v", result, err)
		}
	}
}

// A summary keeps its count, check, entry and refusal reason as typed
// fields and names no target; nothing free-form is copied.
func TestAdmissionSummaryRows(t *testing.T) {
	a := NewAnonymizer(testSalt())
	out, err := a.Action(summaryRow(actionlog.Refused, "policy"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := marshalMap(t, out)
	want := map[string]any{
		"v": 1.0, "format_version": 1.0, "ts": "2026-09-08T10:00:00Z", "op": "respond.block_ip", "action": "block_ip",
		"actor": "daemon", "target_kind": "empty", "reason_kind": "check", "check": "pam_bruteforce", "entry": "challenge_timeout",
		"result": "refused", "refusal": "policy", "has_error": true, "count": 3.0,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summary row:\n got %v\nwant %v", got, want)
	}
	if err = a.VerifyAction(out); err != nil {
		t.Fatal(err)
	}
	for decision := range admissionDecisions {
		if decision == "refused" {
			continue
		}
		out, err := a.Action(summaryRow(actionlog.Result(decision), ""))
		if err != nil || out.Count != 3 || out.Refusal != "" || a.VerifyAction(out) != nil {
			t.Errorf("%s summary -> %+v %v", decision, out, err)
		}
	}
	if d := a.Dropped(); d["action.reason"] != 0 || d["action.error"] != 0 || d["action.actor_detail"] != 0 {
		t.Errorf("typed summary fields counted as dropped: %v", d)
	}
}

func TestAdmissionSummaryRefusals(t *testing.T) {
	for name, mutate := range map[string]func(*actionlog.Record){
		"target":            func(r *actionlog.Record) { r.Target = "203.0.113.9" },
		"finding id":        func(r *actionlog.Record) { r.FindingID = "0123456789abcdef" },
		"action id":         func(r *actionlog.Record) { r.ActionID = "act_0123456789abcdef0123456789abcdef" },
		"incident id":       func(r *actionlog.Record) { r.IncidentID = "incident-raw-0001" },
		"account":           func(r *actionlog.Record) { r.Account = "alice" },
		"command":           func(r *actionlog.Record) { r.Command = []string{"nft"} },
		"undo":              func(r *actionlog.Record) { r.Undo = "csm firewall unblock 203.0.113.9" },
		"file state":        func(r *actionlog.Record) { r.Before = &actionlog.FileState{} },
		"operator":          func(r *actionlog.Record) { r.Actor = actionlog.CLI },
		"legacy action":     func(r *actionlog.Record) { r.Action = "block" },
		"legacy result":     func(r *actionlog.Record) { r.Result = actionlog.Applied },
		"unknown entry":     func(r *actionlog.Record) { r.ActorDetail = "alice" },
		"no entry":          func(r *actionlog.Record) { r.ActorDetail = "" },
		"unknown check":     func(r *actionlog.Record) { r.Reason = "unregistered_check" },
		"free check":        func(r *actionlog.Record) { r.Reason = "brute force from 203.0.113.9" },
		"no check":          func(r *actionlog.Record) { r.Reason = "" },
		"free refusal":      func(r *actionlog.Record) { r.Error = "refused for alice" },
		"no refusal reason": func(r *actionlog.Record) { r.Error = "" },
		"reason on queued":  func(r *actionlog.Record) { r.Result = "queued" },
		"other op":          func(r *actionlog.Record) { r.Op = "respond.kill_process" },
	} {
		r := summaryRow(actionlog.Refused, "policy")
		mutate(&r)
		if _, err := NewAnonymizer(testSalt()).Action(r); err == nil {
			t.Errorf("%s: accepted %+v", name, r)
		}
	}
}

// The verifier holds summaries to the same vocabularies, and a check that
// names a learned identity is a leak.
func TestVerifyAdmissionSummaries(t *testing.T) {
	a := NewAnonymizer(testSalt())
	a.learnAccount("pam_bruteforce")
	r := summaryRow(actionlog.Refused, "policy")
	r.Reason = "wp_login_bruteforce"
	good, err := a.Action(r)
	if err != nil || a.VerifyAction(good) != nil {
		t.Fatalf("valid summary refused: %v %+v", err, good)
	}
	for name, mutate := range map[string]func(*anonAction){
		"learned account as check": func(o *anonAction) { o.Check = "pam_bruteforce" },
		"free check":               func(o *anonAction) { o.Check = "Brute Force" },
		"unknown entry":            func(o *anonAction) { o.Entry = "alice" },
		"unknown refusal":          func(o *anonAction) { o.Refusal = "alice" },
		"no count":                 func(o *anonAction) { o.Count = 0 },
		"summary with target": func(o *anonAction) {
			o.anonTarget = a.mapTarget(parsedTarget{kind: "ip", addr: parseAddr(t, "203.0.113.9")})
		},
		"legacy reason kind": func(o *anonAction) { o.ReasonKind = "scan" },
		"attempt result":     func(o *anonAction) { o.Result = "reserved" },
	} {
		row := good
		mutate(&row)
		if a.VerifyAction(row) == nil {
			t.Errorf("%s: verifier accepted %+v", name, row)
		}
	}
	legacy, err := a.Action(fullRecord())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*anonAction){
		"count on an action":   func(o *anonAction) { o.Count = 1 },
		"check on an action":   func(o *anonAction) { o.Check = "pam_bruteforce" },
		"entry on an action":   func(o *anonAction) { o.Entry = "scan" },
		"refusal on an action": func(o *anonAction) { o.Refusal = "policy" },
		"attempt step":         func(o *anonAction) { o.Result = "observe" },
		"summary reason kind":  func(o *anonAction) { o.ReasonKind = "check" },
	} {
		row := legacy
		mutate(&row)
		if a.VerifyAction(row) == nil {
			t.Errorf("%s: verifier accepted %+v", name, row)
		}
	}
}

// The verifier holds audit rows to the ledger's kinds and steps and an
// address target.
func TestVerifyAdmissionSteps(t *testing.T) {
	a := NewAnonymizer(testSalt())
	good, err := a.Action(admissionRow("block_ip", "ip:203.0.113.9", "reserved"))
	if err != nil || a.VerifyAction(good) != nil {
		t.Fatalf("%+v %v", good, err)
	}
	for name, mutate := range map[string]func(*anonAction){
		"queue decision":  func(o *anonAction) { o.Result = "queued" },
		"legacy action":   func(o *anonAction) { o.Action = "block" },
		"operator":        func(o *anonAction) { o.Actor = string(actionlog.CLI) },
		"no action id":    func(o *anonAction) { o.ActionID = "" },
		"no version":      func(o *anonAction) { o.ActionVersion = 0 },
		"no finding id":   func(o *anonAction) { o.FindingID = "" },
		"no target":       func(o *anonAction) { o.anonTarget = anonTarget{TargetKind: "empty"} },
		"mismatched kind": func(o *anonAction) { o.Action = "block_subnet" },
		"opaque target":   func(o *anonAction) { o.anonTarget = anonTarget{Target: a.ID(idTarget, "csm"), TargetKind: "opaque"} },
	} {
		row := good
		mutate(&row)
		if a.VerifyAction(row) == nil {
			t.Errorf("%s: verifier accepted %+v", name, row)
		}
	}
}

func withReason(r actionlog.Record, reason string) actionlog.Record {
	r.Reason = reason
	return r
}

func parseAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, ok := parseTargetAddr(s)
	if !ok {
		t.Fatalf("bad test address %q", s)
	}
	return addr
}

// withAdmissionResults adds the admission steps and decisions, which a
// manifest always counts, at zero.
func withAdmissionResults(m map[string]any) map[string]any {
	for _, set := range []map[string]bool{admissionAttemptResults, admissionDecisions} {
		for r := range set {
			if _, ok := m[r]; !ok {
				m[r] = 0.0
			}
		}
	}
	return m
}

func withoutAdmissionLink(which string) actionlog.Record {
	r := admissionRow("block_ip", "ip:192.0.2.10", "observe")
	switch which {
	case "action_id":
		r.ActionID = ""
	case "version":
		r.ActionVersion = 0
	case "finding_id":
		r.FindingID = ""
	}
	return r
}

func TestVerifyNonRefusedSummariesRejectRefusalText(t *testing.T) {
	a := NewAnonymizer(testSalt())
	for _, result := range []actionlog.Result{"queued", "coalesced", "observe"} {
		good, err := a.Action(summaryRow(result, ""))
		if err != nil {
			t.Fatal(err)
		}
		good.Refusal, good.HasError = "customer.example", true
		if a.VerifyAction(good) == nil || compareActionShape(good) {
			t.Errorf("%s summary accepted raw refusal text", result)
		}
	}
}

func TestAdmissionSummariesRequireAnHourBoundary(t *testing.T) {
	a := NewAnonymizer(testSalt())
	r := summaryRow("queued", "")
	good, err := a.Action(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Timestamp = r.Timestamp.Add(time.Second)
	if _, err := a.Action(r); err == nil {
		t.Error("accepted a summary outside its hour boundary")
	}
	good.Timestamp = r.Timestamp
	if a.VerifyAction(good) == nil || compareActionShape(good) {
		t.Error("verified a summary outside its hour boundary")
	}
}
