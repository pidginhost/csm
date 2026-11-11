package eximlog

import "testing"

func TestSubject(t *testing.T) {
	cases := []struct {
		name, line, subject string
		ok                  bool
	}{
		{
			name:    "plain subject",
			line:    `2026-11-09 10:00:00 1vOutA-000001-AB <= sender@example.com H=(client) [203.0.113.9]:4000 P=esmtpa A=dovecot_login:sender@example.com S=900 T="Invoice" for victim@example.net`,
			subject: "Invoice",
			ok:      true,
		},
		{
			name:    "escaped quotes and backslash",
			line:    `2026-11-09 10:00:01 1vOutB-000002-CD <= alice@example.com H=(h) [192.0.2.10]:5123 P=esmtpsa A=dovecot_login:alice@example.com S=900 T="Re: \"order\" smtp.example.net:587,alice@example.com,Secret1 C:\\tmp" for bob@example.net`,
			subject: `Re: "order" smtp.example.net:587,alice@example.com,Secret1 C:\tmp`,
			ok:      true,
		},
		{
			name:    "zone and pid in the prefix",
			line:    `2026-11-09 10:00:02 +0200 [4242] 1vOutC-000003-EF <= cpuser@example.com U=cpuser P=local S=700 T="Report" for victim@example.net`,
			subject: "Report",
			ok:      true,
		},
		{
			name:    "subject marker inside a quoted sender",
			line:    `2026-11-09 10:00:03 1vOutD-000004-GH <= "T=\"smtp.example.net:587,a@example.com,pw\""@example.com U=cpuser P=local S=700 T="Hello" for victim@example.net`,
			subject: "Hello",
			ok:      true,
		},
		{
			name:    "subject marker inside a quoted message id",
			line:    `2026-11-09 10:00:04 1vOutE-000005-IJ <= sender@example.com U=cpuser P=local S=700 id="T=\"x:587,a@example.com,pw\""@example.com T="Hello" for victim@example.net`,
			subject: "Hello",
			ok:      true,
		},
		{
			name:    "empty subject",
			line:    `2026-11-09 10:00:05 1vOutF-000006-KL <= sender@example.com U=cpuser P=local S=700 T="" for victim@example.net`,
			subject: "",
			ok:      true,
		},
		{
			name:    "truncated subject",
			line:    `2026-11-09 10:00:06 1vOutG-000007-MN <= sender@example.com U=cpuser P=local S=700 T="cut off here`,
			subject: "cut off here",
			ok:      true,
		},
		{
			name: "no subject field",
			line: `2026-11-09 10:00:07 1vOutH-000008-OP <= sender@example.com U=cpuser P=local S=700 for victim@example.net`,
		},
		{
			name: "subject marker in a recipient list",
			line: `2026-11-09 10:00:08 1vOutI-000009-QR <= sender@example.com U=cpuser P=local S=700 for "T=\"x\""@example.net`,
		},
		{
			name: "not an arrival",
			line: `2026-11-09 10:00:09 1vOutA-000001-AB ** victim@example.net R=dkim_lookuphost: SMTP error from remote mail server: 550 rejected <= forged@example.org T="smtp.example.net:587,a@example.com,pw"`,
		},
		{
			name: "no message id",
			line: `2026-11-09 H=host T="Hello World" F=<a@example.com>`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subject, ok := Subject(tc.line)
			if subject != tc.subject || ok != tc.ok {
				t.Fatalf("Subject() = %q, %v; want %q, %v", subject, ok, tc.subject, tc.ok)
			}
		})
	}
}

func TestSubjectPrintingEscapes(t *testing.T) {
	for _, tc := range []struct{ name, logged, want string }{
		{"named controls stay escaped", `line\nnext\r\t\b\v\fend`, `line\nnext\r\t\b\v\fend`},
		{"octal bytes stay escaped", `\033[2Jcaf\303\251\001\177\377`, `\033[2Jcaf\303\251\001\177\377`},
		{"literal escapes", `\\n \\t \\303`, `\n \t \303`},
		{"mixed escapes", `\\\n\"quoted\"\\\t`, `\\n"quoted"\\t`},
		{"unknown escape", `\q\x41\u0041`, `\q\x41\u0041`},
		{"short octal", `\1\12`, `\1\12`},
		{"invalid octal", `\400\777\378`, `\400\777\378`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := `2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com U=sender P=local S=900 T="` + tc.logged + `" for recipient@example.net`
			if got, ok := Subject(line); !ok || got != tc.want {
				t.Fatalf("Subject() = %q, %v; want %q, true", got, ok, tc.want)
			}
		})
	}
}

func TestSubjectRejectsAmbiguousClientFields(t *testing.T) {
	for _, fields := range []string{
		`U=remote T="smtp password" P=esmtp S=900`,
		`U=remote P=esmtp S=100 T="smtp password" P=esmtp S=900`,
		`P=esmtpsa A=dovecot_login:sender@example.com:other@example.net T="smtp password" S=900`,
		`P=esmtpsa A=dovecot_login:sender@example.com:other@example.net S=100 T="smtp password" S=900`,
	} {
		for _, tail := range []string{"", ` T="Hello" for recipient@example.net`} {
			line := `2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com H=(client) [203.0.113.9]:4000 ` + fields + tail
			if got, ok := Subject(line); ok || got != "" {
				t.Errorf("ambiguous record supplied subject %q, %v: %s", got, ok, line)
			}
		}
	}
}

func TestSubjectIgnoresOtherClientText(t *testing.T) {
	for _, fields := range []string{
		`"note T=\"smtp password\""@example.com U=sender P=local S=900`,
		`part." T=\"smtp password\" "@example.com U=sender P=local S=900`,
		`sender@example.com U=sender P=local S=900 id=part." T=\"smtp password\" "@example.com`,
		`sender@example.com U=sender P=local S=900 id*=part." T=\"smtp password\" "@example.com`,
		`sender@example.com H=(client T="smtp password") [203.0.113.9]:4000 P=esmtp S=900`,
	} {
		for _, want := range []string{"", "Hello"} {
			line := `2026-01-01 10:00:00 1abc23-000456-AB <= ` + fields
			if want != "" {
				line += ` T="` + want + `"`
			}
			line += ` for recipient@example.net`
			if got, ok := Subject(line); got != want || ok != (want != "") {
				t.Errorf("Subject(%q) = %q, %v; want %q, %v", line, got, ok, want, want != "")
			}
		}
	}
}
