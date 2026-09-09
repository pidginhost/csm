package main

import (
	"strings"
	"testing"

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
