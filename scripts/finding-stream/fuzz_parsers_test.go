package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
)

func FuzzAnonymizerTokens(f *testing.F) {
	for _, seed := range []string{"", ".", "--", ".-.-.", "alice", "-alice-", "alice-bob.log", "example.com-ssl_log", "::ffff:203.0.113.9", "address:2001:db8::7", "client4.203.0.113.9.log", `password="alice bob\`, "host-alice.example.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		a := NewAnonymizer(testSalt())
		a.Learn([]alert.AuditEvent{{TenantID: "alice"}, {TenantID: "bob"}})
		out := a.Text(text)
		// A fresh occurrence must remain visible to verification regardless
		// of what replacements or punctuation preceded it.
		problems := strings.Join(a.Verify([]alert.AuditEvent{{Details: out + "\nalice\n203.0.113.9"}}), "\n")
		if !strings.Contains(problems, "account alice") || !strings.Contains(problems, "ipv4 203.0.113.9") {
			t.Fatal("leak checker missed planted identifiers")
		}
		if got := scrubTokens(text, func(core string) string { return core }); got != text {
			t.Fatal("identity token transform changed input")
		}
	})
}

func FuzzDecodeStrict(f *testing.F) {
	for _, seed := range []string{
		"", "{}", "[]", "null", `{"v":1}`, `{"v":1,"v":1}`, `{"V":1}`, `{"v":1}{"v":1}`, `{"v":1} x`, `{"v":1}]`,
		`{"before":null}`, `{"command":["a",1]}`, `{"before":{"exists":true,"extra":1}}`, `{"action_version":-1}`,
		`{"finding_id":"raw-\ud800"}`, `{"finding_id":"raw-\udc00"}`, `{"finding_id":"raw-\ud83d\ude00"}`,
		`{"finding_id":"raw-\\ud800"}`, "{\"finding_id\":\"raw-\xff\"}", `{"ts":"2026-09-08T10:00:00+24:00"}`,
		`{"ts":"2026-09-08T10:00:00Z","op":"respond.block_ip","actor":"daemon","target":"203.0.113.9","result":"applied"}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var rec actionlog.Record
		if decodeStrict(data, &rec) != nil {
			return
		}
		// Whatever the strict decoder accepts must survive its own round trip.
		again, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := decodeStrict(again, &actionlog.Record{}); err != nil {
			t.Fatalf("accepted record does not round-trip: %v", err)
		}
	})
}

func FuzzAddressTarget(f *testing.F) {
	for _, seed := range []string{
		"", "203.0.113.9", "::ffff:203.0.113.9", "2001:DB8::7", "203.0.113.0/24", "2001:db8:1::/48",
		"203.0.113.9:443/tcp", "2001:db8::9:25/udp", "203.0.113.9:0443/tcp", "fe80::1%eth0", "0.0.0.0/0", "alice", "/tcp",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		a := NewAnonymizer(testSalt())
		target, err := a.addressTarget(raw)
		if err != nil {
			return
		}
		// An accepted target is typed, emitted and never the raw text.
		if !a.validTarget(target, addressTargetKinds) {
			t.Fatalf("accepted target fails verification: %+v", target)
		}
		if raw != "" && target.Target == raw {
			t.Fatalf("raw target copied: %q", raw)
		}
	})
}
