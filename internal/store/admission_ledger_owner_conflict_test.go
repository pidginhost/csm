package store

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// All paths that compare a remint with stored or held evidence distinguish
// an owner-only change from an owner change with any other difference.
func TestAdmissionOwnerRemintConflictsAcrossPaths(t *testing.T) {
	for _, path := range []string{"publish", "arrive", "reports only", "ingress"} {
		for _, change := range []struct {
			name     string
			finding  string
			severity admission.Severity
			age      time.Duration
			want     admission.Reason
		}{
			{name: "owner", want: admission.ReasonStaleIdentity},
			{name: "owner and finding", finding: "fedcba9876543210", want: admission.ReasonInvalid},
			{name: "owner and severity", severity: admission.SeverityCritical, want: admission.ReasonInvalid},
			{name: "owner and observation time", age: time.Second, want: admission.ReasonInvalid},
		} {
			t.Run(path+"/"+change.name, func(t *testing.T) {
				f := newLedgerFixture(t)
				first := f.arrival(evidenceSpec{owner: f.owner("alice")})
				remint := f.arrival(evidenceSpec{owner: f.owner("bob"), finding: change.finding, severity: change.severity, age: change.age})
				if remint.Evidence.ID() != first.Evidence.ID() {
					t.Fatal("fixture does not remint the original observation")
				}
				if path == "ingress" {
					in := f.ingress()
					if err := in.Submit(admission.Submission{Kind: first.Request.Kind, Target: first.Request.Target, Evidence: first.Evidence}); err != nil {
						t.Fatal(err)
					}
					err := in.Submit(admission.Submission{Kind: remint.Request.Kind, Target: remint.Request.Target, Evidence: remint.Evidence})
					wantLedgerReason(t, "held remint", err, change.want)
					if got := in.Stats().Counters.Count(admission.CountKey{Event: admission.EventRefused, Reason: change.want}); got != 1 {
						t.Fatalf("refusals = %d, want 1", got)
					}
					held := in.Take(1)
					if len(held) != 1 || !held[0].Submission.Evidence.Equal(first.Evidence) || len(held[0].Reports) != 0 || held[0].Selected != 1 {
						t.Fatalf("refused remint changed held evidence: %+v", held)
					}
					return
				}
				if _, err := f.l.PublishEvidence(first.Evidence); err != nil {
					t.Fatal(err)
				}
				original := f.storedEvidence(first.Evidence.ID())
				if path == "publish" {
					before := f.snapshot()
					published, err := f.l.PublishEvidence(remint.Evidence)
					wantLedgerReason(t, "published remint", err, change.want)
					if published || !reflect.DeepEqual(before, f.snapshot()) {
						t.Fatal("refused publication changed the ledger")
					}
				} else {
					f.begin()
					remint.Reports = []string{"00000000000000a1"}
					if path == "reports only" {
						remint.ReportsOnly = true
						remint.Request = admission.CandidateRequest{}
					}
					results, _, err := f.l.EnqueueGroup([]admission.Arrival{remint}, nil)
					if err != nil || len(results) != 1 {
						t.Fatalf("arrival results = %+v, err = %v", results, err)
					}
					wantLedgerReason(t, "arrived remint", results[0].Err, change.want)
					if results[0].Created || results[0].Candidate != "" || f.candidateCount() != 0 {
						t.Fatalf("refused remint created a candidate: %+v", results[0])
					}
					if got := f.count(admission.CountKey{Event: admission.EventRefused, Reason: change.want, Class: admission.ClassC2, Severity: remint.Evidence.Severity()}); got != 1 {
						t.Fatalf("durable refusals = %d, want 1", got)
					}
				}
				if !bytes.Equal(original, f.storedEvidence(first.Evidence.ID())) {
					t.Fatal("refused remint changed the stored evidence")
				}
				links, dropped, err := f.l.Reports(first.Evidence.ID())
				if err != nil || len(links) != 0 || dropped != 0 {
					t.Fatalf("refused remint linked reports: %v, dropped = %d, err = %v", links, dropped, err)
				}
			})
		}
	}
}
