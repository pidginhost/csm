package store

import (
	"testing"

	"github.com/pidginhost/csm/internal/admission"
)

// The ledger binds an arrival to the address its evidence attributes, as
// the ingress does: a range entry may name a prefix holding it; any other
// target is an attribution refusal (spec 5.8, 5.13).
func TestAdmissionLedgerBindsTheArrivalTarget(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	e := f.mint(evidenceSpec{target: "192.0.2.7", cursor: "bind"})
	prefix := func(raw string) admission.Target {
		p, err := admission.CanonicalPrefix(raw, admission.Caps{IPv6: true})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, req := range map[string]admission.CandidateRequest{
		"another address":           {Kind: admission.KindBlockIP, Target: f.target("192.0.2.8")},
		"a prefix without it":       {Kind: admission.KindBlockSubnet, Target: prefix("198.51.100.0/24"), Entry: admission.EntryMailSubnet},
		"a prefix from a scan root": {Kind: admission.KindBlockSubnet, Target: prefix("192.0.2.0/24")},
		"an explicit scan prefix":   {Kind: admission.KindBlockSubnet, Target: prefix("192.0.2.0/24"), Entry: admission.EntryScan},
		"an incident prefix":        {Kind: admission.KindBlockSubnet, Target: prefix("192.0.2.0/24"), Entry: admission.EntryIncident},
		"an incident spray prefix":  {Kind: admission.KindBlockSubnet, Target: prefix("192.0.2.0/24"), Entry: admission.EntryIncidentSpray},
		"a central prefix":          {Kind: admission.KindBlockSubnet, Target: prefix("192.0.2.0/24"), Entry: admission.EntryCentral},
		"a timeout prefix":          {Kind: admission.KindBlockSubnet, Target: prefix("192.0.2.0/24"), Entry: admission.EntryChallengeTimeout},
		"a netblock prefix":         {Kind: admission.KindBlockSubnet, Target: prefix("192.0.2.0/24"), Entry: admission.EntryNetblock},
		"a permanent prefix":        {Kind: admission.KindBlockSubnet, Target: prefix("192.0.2.0/24"), Entry: admission.EntryPermblock},
	} {
		req.Primary = e.ID()
		got := f.arrive(admission.Arrival{Request: req, Evidence: e})[0]
		if reason, _ := admission.ReasonOf(got.Err); reason != admission.ReasonAttribution || admission.CauseOf(got.Err) != admission.CauseTargetMismatch || got.Created {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	snapshot, err := f.l.QueueSnapshot()
	if err != nil || len(snapshot.Items) != 0 {
		t.Fatalf("refused arrivals changed the queue: %+v %v", snapshot, err)
	}
	for entry, cidr := range map[admission.Entry]string{admission.EntryMailSubnet: "192.0.2.0/24", admission.EntryASNCrawl: "192.0.2.0/25"} {
		got := f.arrive(admission.Arrival{Request: admission.CandidateRequest{Kind: admission.KindBlockSubnet, Target: prefix(cidr), Primary: e.ID(), Entry: entry}, Evidence: e})[0]
		if got.Err != nil || !got.Created {
			t.Fatalf("range entry %s with a contained address: %+v", entry, got)
		}
	}
}
