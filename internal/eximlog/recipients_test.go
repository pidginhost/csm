package eximlog

import (
	"reflect"
	"strings"
	"testing"
)

func TestRecipientsReadsTopLevelForList(t *testing.T) {
	const prefix = "2026-01-01 10:00:00 1abc23-000456-AB <= "
	for _, tc := range []struct {
		name, record string
		want         []string
	}{
		{"single", prefix + `sender@example.com H=mail.example [203.0.113.5]:2525 P=esmtpsa A=dovecot_login:bob@example.net S=100 id=x@example.com T="Hello" for a@example.net`, []string{"a@example.net"}},
		{"several", prefix + `sender@example.com H=(helo) [203.0.113.5]:2525 P=esmtpsa A=dovecot_login:bob@example.net S=100 T="Hello" for a@example.net b@example.org c@example.com`, []string{"a@example.net", "b@example.org", "c@example.com"}},
		{"subject with for", prefix + `sender@example.com H=(helo) [203.0.113.5]:2525 P=esmtpsa A=dovecot_login:bob@example.net S=100 T="an offer for you" for a@example.net`, []string{"a@example.net"}},
		{"subject with escaped quote and for", prefix + `sender@example.com H=(helo) [203.0.113.5]:2525 P=esmtpsa S=100 T="say \" for me" for a@example.net`, []string{"a@example.net"}},
		{"helo with for", prefix + `sender@example.com H=(x for y) [203.0.113.5]:2525 P=esmtpsa A=dovecot_login:bob@example.net S=100 for a@example.net`, []string{"a@example.net"}},
		{"quoted envelope with for", prefix + `"for a@example.net"@example.com H=(helo) [203.0.113.5]:2525 P=esmtpsa S=100 for c@example.org`, []string{"c@example.org"}},
		{"local arrival", prefix + `root@example.com U=root P=local S=100 for alice@example.com`, []string{"alice@example.com"}},
		{"no recipients logged", prefix + `sender@example.com H=(helo) [203.0.113.5]:2525 P=esmtpsa S=100 T="Hello"`, nil},
		{"unclosed subject quote hides the list", prefix + `sender@example.com H=(helo) [203.0.113.5]:2525 P=esmtpsa S=100 T="Hello for a@example.net`, nil},
		{"delivery record", "2026-01-01 10:00:00 1abc23-000456-AB => a@example.net R=dnslookup T=remote_smtp for a@example.net", nil},
		{"embedded arrival in reply", "2026-01-01 10:00:00 1abc23-000456-AB == a@example.net <= sender@example.com for a@example.net", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Recipients(tc.record); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Recipients = %q, want %q", got, tc.want)
			}
		})
	}
}

func FuzzRecipients(f *testing.F) {
	f.Add(`2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com H=(helo) [203.0.113.5]:2525 P=esmtpsa A=dovecot_login:bob@example.net S=100 T="for" for a@example.net b@example.org`)
	f.Add(`2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com T="x for y`)
	f.Add(`2026-01-01 10:00:00 1abc23-000456-AB <= "for x"@example.com U=bob P=local S=1 for`)
	f.Fuzz(func(t *testing.T, line string) {
		for _, r := range Recipients(line) {
			if r == "" || strings.ContainsAny(r, " \t\r\n") || !strings.Contains(line, r) {
				t.Fatalf("recipient %q is not a whitespace-free token of the record", r)
			}
		}
	})
}
