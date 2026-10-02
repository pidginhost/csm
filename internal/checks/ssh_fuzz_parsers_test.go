package checks

import "testing"

// Client-chosen names on failure records and key comments on success records
// must never select a different account or source for a blocking finding.
func FuzzSSHAcceptedRecordFields(f *testing.F) {
	f.Add("Accepted password for root from 192.0.2.50 port 22", "for root from 192.0.2.50 port 22")
	f.Add("sshd[1]: Accepted publickey for root from 192.0.2.50 port 22", "ssh2: ED25519 SHA256:abc")
	f.Add("", "")
	// "from" is a hosting account here, so the tenant shows which field the
	// parser read the account from.
	f.Cleanup(SetHostingAccountLookupForTest(func(name string) string {
		if name == "from" {
			return name
		}
		return ""
	}))
	f.Fuzz(func(t *testing.T, user, suffix string) {
		for _, header := range []string{"Oct  2 12:00:00 host sshd[100]: ", "2026-10-02T12:00:00.123456Z host sshd-session: ", "host sshd: "} {
			for _, message := range []string{
				"Invalid user " + user + " from 203.0.113.9 port 51000",
				"Failed password for invalid user " + user + " from 203.0.113.9 port 51000 ssh2",
				"Connection closed by invalid user " + user + " 203.0.113.9 port 51000 [preauth]",
			} {
				if finding, ok := SSHAcceptedLoginFinding(header+message, nil); ok {
					t.Fatalf("client text created a login finding: %+v", finding)
				}
			}
			finding, ok := SSHAcceptedLoginFinding(header+"Accepted publickey for from from 2001:db8::7 port 50000 "+suffix, nil)
			if !ok || finding.SourceIP != "2001:db8::7" || finding.TenantID != "from" {
				t.Fatalf("key comment changed the account or source: %+v (ok %v)", finding, ok)
			}
		}
	})
}
