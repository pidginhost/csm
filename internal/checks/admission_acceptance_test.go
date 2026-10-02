package checks

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// acceptanceProducer registers one producer that publishes the checks the
// acceptance tables cover. Classification comes from the check, not the
// producer, so one producer stands in for each.
func acceptanceProducer(t *testing.T) *admission.Producer {
	t.Helper()
	reg, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Register(admission.ProducerSpec{
		ID: "acceptance", Entry: admission.EntryScan, Observation: admission.ObservationLogCursor,
		Checks: []string{"email_cloud_relay_abuse", "email_compromised_account", "ssh_login_unknown_ip", "c2_connection", "mail_account_compromised"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func acceptanceMint(p *admission.Producer, check string, sev admission.Severity, cursor string, observed time.Time) (admission.Evidence, admission.Target, error) {
	target, err := admission.CanonicalAddress("192.0.2.10", admission.Caps{})
	if err != nil {
		return admission.Evidence{}, target, err
	}
	e, err := p.Mint(admission.EvidenceInput{
		Check: check, FindingID: "0123456789abcdef", Severity: sev,
		Observation: admission.ObservationRef{Stream: "fixture", Cursor: cursor, Version: 1},
		ObservedAt:  observed, Parser: admission.ParserRef{Name: "fixture", Version: 1}, Target: target,
	})
	return e, target, err
}

// The mail heuristics and an ordinary successful SSH login are local C2
// evidence at any severity, also with a second observation of the same check;
// only a C2 connection and a Critical mail compromise are direct C3.
func TestAdmissionAcceptanceClassifiesProductionChecks(t *testing.T) {
	p := acceptanceProducer(t)
	observed := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		check string
		sev   admission.Severity
		class admission.Class
		c3    bool
	}{
		{"email_cloud_relay_abuse", admission.SeverityHigh, admission.ClassC2, false},
		{"email_cloud_relay_abuse", admission.SeverityCritical, admission.ClassC2, false},
		{"email_compromised_account", admission.SeverityHigh, admission.ClassC2, false},
		{"email_compromised_account", admission.SeverityCritical, admission.ClassC2, false},
		{"ssh_login_unknown_ip", admission.SeverityCritical, admission.ClassC2, false},
		{"c2_connection", admission.SeverityHigh, admission.ClassC3, true},
		{"c2_connection", admission.SeverityCritical, admission.ClassC3, true},
		{"mail_account_compromised", admission.SeverityCritical, admission.ClassC3, true},
	} {
		t.Run(fmt.Sprintf("%s/%s", c.check, c.sev), func(t *testing.T) {
			first, target, err := acceptanceMint(p, c.check, c.sev, "1", observed)
			if err != nil {
				t.Fatal(err)
			}
			again, _, err := acceptanceMint(p, c.check, c.sev, "2", observed.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			a, err := admission.Assess(target, []admission.Evidence{first, again}, observed.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if a.Tier.Class != c.class || a.DirectC3 != c.c3 || a.Corroborated || a.Reserved() != c.c3 {
				t.Fatalf("assessment %+v, want class %s direct %v and no corroboration", a, c.class, c.c3)
			}
		})
	}
}

// A mail compromise from an established multi-mailbox source is High, and
// High is below that check's floor: it never becomes evidence.
func TestAdmissionAcceptanceRefusesHighMailCompromise(t *testing.T) {
	p := acceptanceProducer(t)
	_, _, err := acceptanceMint(p, "mail_account_compromised", admission.SeverityHigh, "1", time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC))
	if reason, ok := admission.ReasonOf(err); !ok || reason != admission.ReasonPolicy {
		t.Fatalf("mint error %v, want a policy refusal", err)
	}
}
