package eximlog

import "testing"

func TestLocalSubmitter(t *testing.T) {
	const prefix = "2026-11-09 10:00:00 1vAbCd-000AbC-1x <= "
	cases := []struct {
		name, line, want string
	}{
		{"php mail", prefix + `info@example.com U=alice P=local S=1200 id=1@example.com T="Order 12" for buyer@example.net`, "alice"},
		{"sendmail -bs", prefix + `info@example.com U=alice P=local-esmtp S=1200 T="Order 12" for buyer@example.net`, "alice"},
		{"escaped quote in sender", prefix + `notice\"tag@example.com U=alice P=local S=1200 for buyer@example.net`, "alice"},
		{"escaped space in sender", prefix + `notice\ tag@example.com U=alice P=local S=1200 for buyer@example.net`, "alice"},
		{"bounce from mailnull", prefix + `<> R=1vAbCd-000AbC-1w U=mailnull P=local S=800 T="Mail delivery failed" for info@example.com`, "mailnull"},
		{"authenticated smtp", prefix + `info@example.com H=(client) [203.0.113.7]:51000 P=esmtpsa X=TLS1.3 A=dovecot_login:info@example.com S=1200 for buyer@example.net`, ""},
		{"local caller that authenticated", prefix + `info@example.com U=alice P=local-esmtpa A=dovecot_login:info@example.com S=1200 for buyer@example.net`, ""},
		{"remote sender with forged subject", prefix + `x@example.org H=mx.example.org [203.0.113.9]:40000 P=esmtps S=900 T="hi U=alice P=local B=redirect_resolver" for info@example.com`, ""},
		{"remote ident user", prefix + `x@example.org H=mx.example.org [203.0.113.9]:40000 U=alice P=esmtp S=900 for info@example.com`, ""},
		{"forged fields after size", prefix + `x@example.org P=esmtp S=900 U=alice P=local for info@example.com`, ""},
		{"not an arrival", `2026-11-09 10:00:00 1vAbCd-000AbC-1x => buyer@example.net U=alice P=local R=dkim_lookuphost T=dkim_remote_smtp`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LocalSubmitter(tc.line); got != tc.want {
				t.Fatalf("LocalSubmitter = %q, want %q", got, tc.want)
			}
		})
	}
}
