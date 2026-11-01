package incident

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A listed address seen failing mailbox logins is brute-forcing mail, so its
// reputation finding opens the same incident kind as the brute-force finding
// that may follow, keyed on the same address.
func TestMailLoginReputationIsMailboxBruteforce(t *testing.T) {
	f := alert.Finding{Check: "ip_reputation", Severity: alert.Critical, SourceIP: "203.0.113.7", MailLoginFailure: true}
	if got := ClassifyKind(f); got != KindMailboxBruteforce {
		t.Fatalf("kind = %s, want %s", got, KindMailboxBruteforce)
	}
	if got := KeyFor(f); got != (Key{RemoteIP: "203.0.113.7"}) {
		t.Fatalf("key = %+v, want the attacker address", got)
	}
}

func TestCorrelatorFilesMailLoginReputationAsMailboxBruteforce(t *testing.T) {
	c := newTestCorrelator()
	id, created, err := c.OnFinding(alert.Finding{Check: "ip_reputation", Severity: alert.Critical, SourceIP: "203.0.113.7", MailLoginFailure: true})
	if err != nil || !created {
		t.Fatalf("OnFinding = %q, %v, %v; want a new incident", id, created, err)
	}
	joined, created, err := c.OnFinding(alert.Finding{Check: "mail_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.7"})
	if err != nil || created || joined != id {
		t.Fatalf("brute force finding opened %q (created %v, err %v), want it to join %q", joined, created, err, id)
	}
	if inc, ok := c.Get(id); !ok || inc.Kind != KindMailboxBruteforce {
		t.Fatalf("incident = %+v, want kind %s", inc, KindMailboxBruteforce)
	}
	web, _, _ := c.OnFinding(alert.Finding{Check: "ip_reputation", Severity: alert.High, SourceIP: "203.0.113.8"})
	if inc, ok := c.Get(web); !ok || inc.Kind != KindWebAttack {
		t.Fatalf("web sighting incident = %+v, want kind %s", inc, KindWebAttack)
	}
}
