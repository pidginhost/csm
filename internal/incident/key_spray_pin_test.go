package incident

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A password spray opens a mailbox brute-force incident keyed on its subnet
// text, whatever mailbox it carries, and an incident block never targets the
// subnet. Persisted incidents match new findings by that key.
func TestSprayPinIncidentKeysOnTheSubnet(t *testing.T) {
	for _, check := range []string{"mail_subnet_spray", "smtp_subnet_spray"} {
		f := alert.Finding{Check: check, Severity: alert.Critical, SourceIP: "203.0.113.0/24", Mailbox: "alice@example.com"}
		if kind := ClassifyKind(f); kind != KindMailboxBruteforce {
			t.Errorf("%s: kind %v, want mailbox brute force", check, kind)
		}
		if k := KeyFor(f); k != (Key{RemoteIP: "203.0.113.0/24"}) {
			t.Errorf("%s: key %+v, want the subnet as remote address", check, k)
		}
		if ip := normalizeIncidentRemoteIP(f.SourceIP); ip != "" {
			t.Errorf("%s: block target %q, want none", check, ip)
		}
	}
}
