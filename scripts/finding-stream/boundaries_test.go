package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

func TestStrictDecoderPreservesIdentityBytes(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte("{\"finding_id\":\"raw-\xff\"}"),
		[]byte(`{"finding_id":"raw-\ud800"}`),
		[]byte(`{"finding_id":"raw-\udc00"}`),
		[]byte(`{"finding_id":"raw-\ud800\u0041"}`),
	} {
		if err := decodeStrict(raw, &actionlog.Record{}); err == nil {
			t.Fatal("invalid Unicode was accepted and silently replaced in an identity")
		}
	}
	for _, raw := range []string{
		`{"finding_id":"raw-\ud83d\ude00"}`,
		`{"finding_id":"raw-\ufffd"}`,
		`{"finding_id":"raw-\\ud800"}`,
	} {
		if err := decodeStrict([]byte(raw), &actionlog.Record{}); err != nil {
			t.Fatalf("valid Unicode refused: %v", err)
		}
	}
}

func TestStrictDecoderRejectsUnencodableTime(t *testing.T) {
	raw := []byte(`{"ts":"2026-09-08T10:00:00+24:00"}`)
	var rec actionlog.Record
	if err := decodeStrict(raw, &rec); err == nil {
		_, marshalErr := json.Marshal(rec)
		t.Fatalf("unencodable time accepted: marshal error = %v", marshalErr)
	}
}

func TestVerifyEmbeddedRawIDs(t *testing.T) {
	a := NewAnonymizer(testSalt())
	raw := "0123456789abcdef"
	a.LearnActions([]actionlog.Record{{FindingID: raw}})
	for _, text := range []string{raw, "inc_" + raw, "finding-" + raw + "-backup", "prefix" + raw + "suffix"} {
		if problems := a.Verify([]alert.AuditEvent{{Details: text}}); len(problems) == 0 {
			t.Error("raw ID survived inside a longer token")
		}
	}
	for _, event := range []alert.AuditEvent{{Check: "check_" + raw}, {Severity: raw}} {
		if problems := a.Verify([]alert.AuditEvent{event}); len(problems) == 0 {
			t.Error("raw ID survived in preserved metadata")
		}
	}
}

func TestAddressMappingAgreesAcrossStreams(t *testing.T) {
	for _, raw := range []string{"2001:0DB8:0000:0000:0000:0000:0000:0007", "::ffff:203.0.113.9", "::ffff:cb00:7109"} {
		a := NewAnonymizer(testSalt())
		target, err := a.addressTarget(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := a.Text("from " + raw); got != "from "+target.Target {
			t.Errorf("finding and typed target disagree: %q != %q", got, target.Target)
		}
	}
}

func TestTypedVerifiersRequireExactEmittedTokens(t *testing.T) {
	a := NewAnonymizer(testSalt())
	rec := fullRecord()
	rec.Target = "2001:db8::7"
	good, err := a.Action(rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"host", "account", "address"} {
		o := good
		switch field {
		case "host":
			o.Hostname = "host-" + strings.ToUpper(strings.TrimPrefix(o.Hostname, "host-"))
		case "account":
			o.Account = "acct-" + strings.ToUpper(strings.TrimPrefix(o.Account, "acct-"))
		case "address":
			o.Target = strings.ToUpper(o.Target)
		}
		if o == good {
			t.Fatalf("%s fixture did not alter the token", field)
		}
		if verifyErr := a.VerifyAction(o); verifyErr == nil {
			t.Errorf("%s: non-emitted spelling accepted", field)
		}
	}
	fw, err := a.FirewallAudit(firewall.AuditEntry{Timestamp: recordTS, Action: "block", IP: rec.Target})
	if err != nil {
		t.Fatal(err)
	}
	fw.Target = strings.ToUpper(fw.Target)
	if err := a.VerifyFirewallAudit(fw); err == nil {
		t.Error("firewall accepted a non-emitted spelling")
	}
	foreign := NewAnonymizer(bytes.Repeat([]byte{0x99}, 32)).ID(idFinding, "raw")
	if problems := a.Verify([]alert.AuditEvent{{FindingID: foreign}}); len(problems) == 0 {
		t.Error("finding verifier accepted a foreign-salt ID")
	}
}
