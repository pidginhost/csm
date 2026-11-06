package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	"github.com/pidginhost/csm/internal/reporting"
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

// Incident kinds must not change the reportable abuse set or hide incident
// blocks from the attacker side of the digest.
func TestMailLoginReputationReportingAndDigest(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		AddressEvidence: func(check string, sev alert.Severity) bool {
			return check == "ip_reputation" || registryEvidence(check, sev)
		},
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled: true, BlockAtSeverity: "critical",
		},
		OnIncidentBlock: cap.recordOK,
	})
	now := time.Now()
	f := alert.Finding{Check: "ip_reputation", Severity: alert.Critical, SourceIP: "203.0.113.7", MailLoginFailure: true, Timestamp: now}
	if _, _, err := c.OnFinding(f); err != nil {
		t.Fatal(err)
	}
	if cap.len() != 1 {
		t.Fatalf("incident block calls = %d, want 1", cap.len())
	}
	digest := blockdigest.New(blockdigest.Options{Watch: true, SendOn: "any"})
	digest.Observe(cap.calls[0].IP, cap.calls[0].Reason, now)
	if got := digest.Drain(); got.Total != 1 || got.AttackerCount != 1 || got.CustomerCount != 0 {
		t.Fatalf("mail incident block digest = %+v", got)
	}
	gate := reporting.Gate{Enabled: map[reporting.Class]bool{reporting.ClassBruteforce: true}}
	if _, ok := gate.Consider(f); ok {
		t.Fatal("reputation match reported back as locally confirmed abuse")
	}
	for _, check := range []string{"smtp_bruteforce", "mail_bruteforce"} {
		f.Check, f.MailLoginFailure = check, false
		report, ok := gate.Consider(f)
		if !ok || report.Class != reporting.ClassBruteforce || report.IP != f.SourceIP {
			t.Fatalf("%s report = %+v, %v", check, report, ok)
		}
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
