package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestIrregularNamesPreservePunctuation(t *testing.T) {
	for _, name := range []string{"-", "_", ".", "--", "_._", "\u2603"} {
		t.Run(name, func(t *testing.T) {
			a := NewAnonymizer(testSalt())
			a.Learn([]alert.AuditEvent{{TenantID: name}})
			text := "probe " + name + " -- status _ . prefix---suffix prefix...suffix"
			if got := a.Text(text); got != text {
				t.Fatalf("punctuation rewritten: %q", got)
			}
			if problems := a.Verify([]alert.AuditEvent{{Message: text}}); len(problems) == 0 {
				t.Fatal("ambiguous punctuation no longer refuses the run")
			}
			_, err := newRun().transform(NewAnonymizer(testSalt()), &inputs{
				findings: []alert.AuditEvent{{TenantID: name, Message: text}},
			})
			if !errors.Is(err, errLeak) {
				t.Fatalf("run accepted ambiguous punctuation: %v", err)
			}
		})
	}
}

func TestIrregularNamePrecedenceAndLateLearning(t *testing.T) {
	a := NewAnonymizer(testSalt())
	a.Learn([]alert.AuditEvent{{TenantID: "ops_team"}, {TenantID: "ops_team_backup"}})
	if got, want := a.Text("ops_team_backup ops_team"), a.Account("ops_team_backup")+" "+a.Account("ops_team"); got != want {
		t.Fatalf("overlapping names: got %q, want %q", got, want)
	}
	a.Learn([]alert.AuditEvent{{Domain: "ops_team"}})
	if got, want := a.Text("OPS_TEAM"), a.Domain("ops_team"); got != want {
		t.Fatalf("late domain: got %q, want %q", got, want)
	}
	a.Learn([]alert.AuditEvent{{Hostname: "ops_team"}})
	if got, want := a.Text("OPS_TEAM"), a.Host("ops_team"); got != want {
		t.Fatalf("late host: got %q, want %q", got, want)
	}
	a.Learn([]alert.AuditEvent{{TenantID: "ops_team_backup_extra"}})
	if got, want := a.Text("ops_team_backup_extra"), a.Account("ops_team_backup_extra"); got != want {
		t.Fatalf("late longest name: got %q, want %q", got, want)
	}
	a.Learn([]alert.AuditEvent{{TenantID: "team_backup"}})
	if got, want := a.Text("Xops_team_backup"), "Xops_"+a.Account("team_backup"); got != want {
		t.Fatalf("late suffix: got %q, want %q", got, want)
	}
}

func TestIrregularVerifierIgnoresReplacementIndex(t *testing.T) {
	a := NewAnonymizer(testSalt())
	a.Learn([]alert.AuditEvent{{TenantID: "mx_login", Hostname: "web_07", Domain: "test_site"}})
	// Simulate a broken or empty replacement index. The separately learned
	// identities must still be found in unmodified text by the verifier.
	a.irregular = nameIndex{}
	for _, raw := range []string{"mx_login", "web_07", "test_site"} {
		if got := a.Verify([]alert.AuditEvent{{Message: raw}}); len(got) == 0 {
			t.Errorf("verifier missed %q with broken replacement index", raw)
		}
	}
}

func TestIrregularNamesPreserveEmittedTokens(t *testing.T) {
	for _, kind := range []string{"account", "host", "domain", "mailbox"} {
		t.Run(kind, func(t *testing.T) {
			a := NewAnonymizer(testSalt())
			var emitted string
			switch kind {
			case "account":
				emitted = a.Account("sample_login")
			case "host":
				emitted = a.Host("web_07.example.net")
			case "domain":
				emitted = a.Domain("sample_site.example.net")
			case "mailbox":
				emitted = a.Email("sample_login")
			}
			// A learned value overlaps a real output token, including its
			// punctuation. Such a match must not consume any of that token.
			a.Learn([]alert.AuditEvent{{TenantID: "." + emitted}})
			text := "[." + emitted + "]"
			if got := a.Text(text); got != text {
				t.Fatalf("emitted %s changed: %q", kind, got)
			}
			// Looking like an output token is insufficient without emission.
			other := NewAnonymizer(testSalt())
			other.Learn([]alert.AuditEvent{{TenantID: "." + emitted}})
			if got := other.Text(text); got == text {
				t.Fatal("unemitted lookalike was exempted")
			}
		})
	}
}

func TestIrregularNamesUseOriginalSpans(t *testing.T) {
	for _, c := range []struct {
		name string
		text string
	}{
		{".probe", "/app/.probe.example.net"},
		{"ops_@queue", "login ops_@queue failed"},
		{"ops_@example.net_extra", "login ops_@example.net_extra failed"},
		{"ops_", "ops__backup"},
		{"\u0130_ops", "login \u0130_OPS failed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := NewAnonymizer(testSalt())
			a.Learn([]alert.AuditEvent{{TenantID: c.name}})
			got := a.Text(c.text)
			if !strings.Contains(got, a.Account(c.name)) {
				t.Fatalf("whole identity lost: %q", got)
			}
			if problems := a.Verify([]alert.AuditEvent{{Message: got}}); len(problems) != 0 {
				t.Fatalf("scrubbed output refused: %v", problems)
			}
			if problems := a.Verify([]alert.AuditEvent{{Message: c.text}}); len(problems) == 0 {
				t.Fatal("independent verifier missed raw identity")
			}
		})
	}
}

func TestIrregularNamesKeepMailboxAndHomeMappings(t *testing.T) {
	a := NewAnonymizer(testSalt())
	a.Learn([]alert.AuditEvent{{TenantID: "mx_test"}, {TenantID: ".probe"}})
	for _, c := range []struct{ text, want string }{
		{"mx_test@example.net", a.Email("mx_test@example.net")},
		{"mx_test@", a.Email("mx_test") + "@"},
		{"/home/.probe/auth.json", "/home/" + a.Account(".probe") + "/auth.json"},
	} {
		if got := a.Text(c.text); got != c.want {
			t.Errorf("%q: got %q, want %q", c.text, got, c.want)
		}
	}
	// Learning an output-shaped suffix must not corrupt a mailbox emitted
	// earlier in the very same Text call.
	a.Learn([]alert.AuditEvent{{TenantID: "example_"}})
	if got, want := a.Text("mx_test@example.net_ "), a.Email("mx_test@example.net")+"_ "; got != want {
		t.Errorf("mailbox pseudonym corrupted: got %q, want %q", got, want)
	}
}

func BenchmarkIrregularNames(b *testing.B) {
	for _, count := range []int{10, 1000, 5000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			a := NewAnonymizer(testSalt())
			for i := range count {
				a.Learn([]alert.AuditEvent{{TenantID: fmt.Sprintf("login_%05d", i)}})
			}
			text := "Mail authentication failure for login_00007 from 203.0.113.9; retry from the same client"
			a.Text(text)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				a.Text(text)
			}
		})
	}
}

func BenchmarkIrregularRows(b *testing.B) {
	a := NewAnonymizer(testSalt())
	for i := range 5000 {
		a.Learn([]alert.AuditEvent{{TenantID: fmt.Sprintf("login_%05d", i)}})
	}
	event := alert.AuditEvent{
		TenantID: "login_00007", Hostname: "web_07.example.net",
		Message: "Mail authentication failure for login_00007 from 203.0.113.9",
		Details: "Dovecot authentication data (set_id=login_00007) retry as LOGIN_00007",
	}
	a.Learn([]alert.AuditEvent{event})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		out := a.Event(event)
		if problems := a.Verify([]alert.AuditEvent{out}); len(problems) != 0 {
			b.Fatalf("scrubbed output refused: %v", problems)
		}
	}
}

func BenchmarkIrregularSharedPrefix(b *testing.B) {
	a := NewAnonymizer(testSalt())
	prefix := strings.Repeat("ops_", 1000)
	a.Learn([]alert.AuditEvent{{TenantID: prefix + "end"}})
	text := prefix + "other"
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		a.Text(text)
	}
}
