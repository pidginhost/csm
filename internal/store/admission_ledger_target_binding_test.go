package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
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

// Published evidence cannot bypass target binding by entering the ledger
// directly, including a repeated request for a permitted range candidate.
func TestAdmissionLedgerBindsDirectRequests(t *testing.T) {
	f := newLedgerFixture(t)
	root := f.published(evidenceSpec{target: "192.0.2.7"})
	prefix, err := admission.CanonicalPrefix("192.0.2.0/24", admission.Caps{})
	if err != nil {
		t.Fatal(err)
	}
	req := f.request("192.0.2.7", root)
	req.Kind, req.Target = admission.KindBlockSubnet, prefix
	for _, queued := range []bool{false, true} {
		if queued {
			req.Entry = admission.EntryMailSubnet
			if _, created, err := f.l.Enqueue(req); err != nil || !created {
				t.Fatalf("permitted range: created=%v, err=%v", created, err)
			}
		}
		for _, entry := range []admission.Entry{0, admission.EntryScan, admission.EntryChallengeTimeout} {
			req.Entry = entry
			_, created, err := f.l.Enqueue(req)
			if created || admission.CauseOf(err) != admission.CauseTargetMismatch {
				t.Errorf("queued=%v, entry=%s: created=%v, err=%v", queued, entry, created, err)
			}
		}
		want := 0
		if queued {
			want = 1
		}
		if got := f.candidateCount(); got != want {
			t.Fatalf("queued=%v: %d candidates, want %d", queued, got, want)
		}
	}
}

// A prefix queued under an entry that no longer permits ranges must be
// refused when retained work is revalidated or selected for an attempt.
func TestAdmissionLedgerRechecksRetainedTargetBinding(t *testing.T) {
	for _, stage := range []string{"revalidate", "reserve"} {
		t.Run(stage, func(t *testing.T) {
			f := newLedgerFixture(t)
			root := f.published(evidenceSpec{target: "192.0.2.7"})
			prefix, err := admission.CanonicalPrefix("192.0.2.0/24", admission.Caps{})
			if err != nil {
				t.Fatal(err)
			}
			req := f.request("192.0.2.7", root)
			req.Kind, req.Target, req.Entry = admission.KindBlockSubnet, prefix, admission.EntryMailSubnet
			legacy, id := f.enqueue(req)
			if err := f.l.Revalidate(); err != nil {
				t.Fatal(err)
			}
			if got, err := f.l.Candidate(id); err != nil || got.State != admission.StateQueued {
				t.Fatalf("permitted range did not stay queued: %+v, err=%v", got, err)
			}
			// Reproduce the stored shape accepted before target binding;
			// the entry is not part of the candidate's identity.
			legacy.Entry = admission.EntryScan
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return putCandidate(tx, legacy) }); err != nil {
				t.Fatal(err)
			}
			if stage == "reserve" {
				before := f.snapshot()
				_, _, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
				if reason, _ := admission.ReasonOf(err); granted || reason != admission.ReasonAttribution {
					t.Fatalf("unbound reservation: granted=%v, err=%v", granted, err)
				}
				if !reflect.DeepEqual(before, f.snapshot()) {
					t.Fatal("refused reservation changed ledger records")
				}
			} else {
				if err := f.l.Revalidate(); err != nil {
					t.Fatal(err)
				}
				got, err := f.l.Candidate(id)
				if err != nil || got.State != admission.StateRefused || got.Reason != admission.ReasonAttribution {
					t.Fatalf("unbound candidate after revalidation: %+v, err=%v", got, err)
				}
			}
		})
	}
}
