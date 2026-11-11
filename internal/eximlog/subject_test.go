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
