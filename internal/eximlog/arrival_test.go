package eximlog

import "testing"

func TestArrival(t *testing.T) {
	cases := []struct {
		name, line, id, sender string
		ok                     bool
	}{
		{
			name:   "authenticated submission",
			line:   `2026-11-09 10:00:00 1vOutA-000001-AB <= sender@example.com H=(client) [203.0.113.9]:4000 P=esmtpa A=dovecot_login:sender@example.com S=900 T="Invoice" for victim@example.net`,
			id:     "1vOutA-000001-AB",
			sender: "sender@example.com",
			ok:     true,
		},
		{
			name:   "zone and pid in the prefix",
			line:   `2026-11-09 10:00:01 +0200 [4242] 1vOutB-000002-CD <= cpuser@example.com U=cpuser P=local S=700 for victim@example.net`,
			id:     "1vOutB-000002-CD",
			sender: "cpuser@example.com",
			ok:     true,
		},
		{
			name:   "quoted local part keeps its space",
			line:   `2026-11-09 10:00:02 1vOutC-000003-EF <= "john doe"@example.com U=cpuser P=local S=700 for victim@example.net`,
			id:     "1vOutC-000003-EF",
			sender: `"john doe"@example.com`,
			ok:     true,
		},
		{
			name:   "bounce",
			line:   `2026-11-09 10:00:03 1vBncD-000004-GH <= <> R=1vOutA-000001-AB U=mailnull P=local S=1200`,
			id:     "1vBncD-000004-GH",
			sender: "<>",
			ok:     true,
		},
		{
			name: "arrival marker inside a delivery failure",
			line: `2026-11-09 10:00:04 1vOutA-000001-AB ** victim@example.net R=dkim_lookuphost: SMTP error from remote mail server: 550 rejected <= forged@example.org`,
		},
		{
			name: "two fields before the marker",
			line: `1681234567 ABC123 <= sender@example.com H=mail.example.com`,
		},
		{
			name: "no envelope sender",
			line: `2026-11-09 10:00:05 1vOutE-000005-IJ <=  H=(client) [203.0.113.9]:4000`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, sender, ok := Arrival(tc.line)
			if id != tc.id || sender != tc.sender || ok != tc.ok {
				t.Errorf("Arrival = (%q, %q, %v), want (%q, %q, %v)", id, sender, ok, tc.id, tc.sender, tc.ok)
			}
		})
	}
}

func TestSubmissionDoesNotBroadenTenantIdentity(t *testing.T) {
	for _, auth := range []string{
		"plain:alice@example.com",
		"plain",
		`dovecot_login:"john doe"@example.com`,
		"dovecot_login:alice@example.com@example.net",
		"dovecot_login:@example.com",
		"dovecot_login:alice@",
	} {
		line := "2026-01-01 10:00:00 1vOutA-000001-AB <= sender@example.com H=(client) [203.0.113.9]:4000 P=esmtpsa A=" + auth + " S=900"
		if !IsSubmission(line) {
			t.Errorf("authenticated submission skipped with A=%s", auth)
		}
		if got := Submitter(line); got != "" {
			t.Errorf("unverified tenant identity accepted with A=%s: %q", auth, got)
		}
		if got := AuthenticatedUser(line); got != "" {
			t.Errorf("unverified mailbox accepted with A=%s: %q", auth, got)
		}
	}
}
