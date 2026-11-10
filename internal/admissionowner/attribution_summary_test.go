package admissionowner

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// A root can lose its attribution before submission or queue placement, or
// while its candidate waits in the queue. Every refusal path must keep the
// cause in the hourly summary: submission, placement, revalidation and the
// recheck of a turn's picks.
func TestOwnerSummarizesRetainedAttributionRefusals(t *testing.T) {
	for _, stage := range []string{"respond", "drain", "revalidate", "turn"} {
		t.Run(stage, func(t *testing.T) {
			var kinds atomic.Uint32
			kinds.Store(uint32(admission.Attributions(admission.AttributionPeer)))
			reg, err := admission.NewRegistry(func(check string) (string, admission.Policy, bool) {
				return check, admission.Policy{Family: admission.FamilySSH, Basis: admission.BasisLocal,
					Attribution: admission.AttributionSet(kinds.Load())}, check == "ssh_brute"
			})
			if err != nil {
				t.Fatal(err)
			}
			p, err := reg.Register(admission.ProducerSpec{ID: "sshd_log", Entry: admission.EntryScan,
				Observation: admission.ObservationLogCursor, Checks: []string{"ssh_brute"},
				Attribution: admission.Attributions(admission.AttributionPeer)})
			if err != nil {
				t.Fatal(err)
			}
			reg.Seal()
			previous := buildRegistry
			buildRegistry = func() (*admission.Registry, map[admission.ProducerID]*admission.Producer, error) {
				return reg, map[admission.ProducerID]*admission.Producer{p.ID(): p}, nil
			}
			t.Cleanup(func() { buildRegistry = previous })
			f := newOwnerFixture(t)
			comparisonClock(t, f.host.now)
			sink := &actionSink{}
			opts := respondOptions(f)
			opts.WriteAudit = sink.write
			o := f.start(opts)
			finding := sshFinding(f.host.now(), "offset=1", alert.High)
			root, err := o.Mint(finding)
			if err != nil {
				t.Fatal(err)
			}
			switch stage {
			case "respond":
				kinds.Store(0)
				if err := o.Respond(admission.KindBlockIP, finding.SourceIP, root, 0); admission.CauseOf(err) != admission.CauseKindNotAllowed {
					t.Fatalf("retained root refusal: %v", err)
				}
			case "revalidate", "turn":
				// Queued while the kind was allowed, then refused by a
				// later check of the waiting candidate.
				if err := o.Respond(admission.KindBlockIP, finding.SourceIP, root, 0); err != nil {
					t.Fatal(err)
				}
				if err := o.do(o.drain); err != nil {
					t.Fatal(err)
				}
				kinds.Store(0)
				later := func() error { return o.ledger.Revalidate() }
				if stage == "turn" {
					later = o.turn
				}
				if err := o.do(later); err != nil {
					t.Fatal(err)
				}
			default:
				// Two selections of one observation must keep their count
				// when the ledger refuses the coalesced arrival.
				for range 2 {
					if err := o.Respond(admission.KindBlockIP, finding.SourceIP, root, 0); err != nil {
						t.Fatal(err)
					}
				}
				kinds.Store(0)
				if err := o.do(o.drain); err != nil {
					t.Fatal(err)
				}
			}
			if err := o.do(func() error { o.writeComparison(true); return nil }); err != nil {
				t.Fatal(err)
			}
			sink.mu.Lock()
			defer sink.mu.Unlock()
			var refusals []actionlog.Record
			for _, row := range sink.recs {
				if row.Count > 0 && row.Result == actionlog.Refused {
					refusals = append(refusals, row)
				}
			}
			want := uint64(1)
			if stage == "drain" {
				want = 2
			}
			if len(refusals) != 1 || refusals[0].Count != want || refusals[0].Error != "attribution" || refusals[0].Cause != "kind_not_allowed" {
				t.Fatalf("refusals = %+v, want one attribution/kind_not_allowed summary counting %d", refusals, want)
			}
		})
	}
}

// A later refusal counts in the hour the ledger ended it, even when an
// unrelated arrival already opened a newer comparison hour and the report
// arrives on another goroutine. The owner's own clock is never read.
func TestOwnerLaterRefusalKeepsLedgerHourAfterNewerArrival(t *testing.T) {
	var kinds atomic.Uint32
	kinds.Store(uint32(admission.Attributions(admission.AttributionPeer)))
	reg, err := admission.NewRegistry(func(check string) (string, admission.Policy, bool) {
		return check, admission.Policy{Family: admission.FamilySSH, Basis: admission.BasisLocal,
			Attribution: admission.AttributionSet(kinds.Load())}, check == "ssh_brute"
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Register(admission.ProducerSpec{ID: "sshd_log", Entry: admission.EntryScan,
		Observation: admission.ObservationLogCursor, Checks: []string{"ssh_brute"},
		Attribution: admission.Attributions(admission.AttributionPeer)})
	if err != nil {
		t.Fatal(err)
	}
	reg.Seal()
	previous := buildRegistry
	buildRegistry = func() (*admission.Registry, map[admission.ProducerID]*admission.Producer, error) {
		return reg, map[admission.ProducerID]*admission.Producer{p.ID(): p}, nil
	}
	t.Cleanup(func() { buildRegistry = previous })
	f := newOwnerFixture(t)
	ledgerAt := f.host.now()
	h := ledgerAt.UTC().Truncate(time.Hour)
	// Funnels count by delivery time, an hour after the ledger's.
	comparisonClock(t, func() time.Time { return h.Add(time.Hour + 10*time.Minute) })
	sink := &actionSink{}
	opts := respondOptions(f)
	opts.WriteAudit = sink.write
	o := f.start(opts)
	finding := sshFinding(ledgerAt, "offset=1", alert.High)
	root, err := o.Mint(finding)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Respond(admission.KindBlockIP, finding.SourceIP, root, 0); err != nil {
		t.Fatal(err)
	}
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	// An unrelated arrival opens the comparison's next hour.
	unrelated := compareKey{entry: admission.EntryScan, check: "ssh_brute", kind: admission.KindBlockIP, decision: decisionObserve}
	o.compare.add(unrelated)
	ownerNow := h.Add(3*time.Hour + 5*time.Minute)
	if err := o.do(func() error { o.now = ownerNow; return nil }); err != nil {
		t.Fatal(err)
	}
	kinds.Store(0)
	done := make(chan error)
	go func() { done <- o.ledger.Revalidate() }()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var stillOwnerNow bool
	if err := o.do(func() error { stillOwnerNow = o.now.Equal(ownerNow); o.writeComparison(true); return nil }); err != nil {
		t.Fatal(err)
	}
	if !stillOwnerNow {
		t.Fatal("the report changed the owner's clock")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	var refusals, observes []actionlog.Record
	for _, row := range sink.recs {
		switch {
		case row.Count > 0 && row.Result == actionlog.Refused:
			refusals = append(refusals, row)
		case row.Count > 0 && row.Result == actionlog.Result(decisionObserve):
			observes = append(observes, row)
		}
	}
	if len(refusals) != 1 || refusals[0].Count != 1 || refusals[0].Cause != "kind_not_allowed" || !refusals[0].Timestamp.Equal(h.Add(time.Hour)) {
		t.Fatalf("refusals = %+v, want one kind_not_allowed row ending the ledger's hour %v", refusals, h.Add(time.Hour))
	}
	if len(observes) != 1 || !observes[0].Timestamp.Equal(h.Add(2*time.Hour)) {
		t.Fatalf("unrelated rows = %+v, want one ending %v", observes, h.Add(2*time.Hour))
	}
}

// A preview the ledger refuses for attribution ends the pick and counts one
// refused row with its cause, in the hour of the ledger time it ended at,
// even after an unrelated arrival opened a newer hour. A pick whose ending
// fails counts nothing.
func TestOwnerRefusedPreviewKeepsCause(t *testing.T) {
	refusal := &admission.Error{Reason: admission.ReasonAttribution, Cause: admission.CauseTargetMismatch, Detail: "preview refused"}
	for _, closeDB := range []bool{false, true} {
		name := "ended"
		if closeDB {
			name = "ending fails"
		}
		t.Run(name, func(t *testing.T) {
			withLiveExecution(t, false)
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			h := f.host.now().UTC().Truncate(time.Hour)
			comparisonClock(t, func() time.Time { return h.Add(time.Hour + 10*time.Minute) })
			sink := &actionSink{}
			opts := executeOptions(f, newFakeBlocks())
			opts.WriteAudit = sink.write
			o := f.start(opts)
			setOwnerHook(t, o, &observeLedger, func(*store.AdmissionLedger, admission.CandidateID, admission.Lane, time.Time) (admission.Candidate, admission.AttemptRecord, bool, admission.EvictionVictim, error) {
				if closeDB {
					if err := f.db.Close(); err != nil {
						t.Error(err)
					}
				}
				return admission.Candidate{}, admission.AttemptRecord{}, false, admission.EvictionVictim{}, refusal
			})
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			o.compare.add(compareKey{entry: admission.EntryScan, check: "ssh_brute", kind: admission.KindBlockIP, decision: decisionObserve})
			err := o.do(o.turn)
			if closeDB {
				if err == nil {
					t.Fatal("a failed ending did not fail the turn")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if c, cerr := o.ledger.Candidate(id); cerr != nil || c.State != admission.StateRefused || c.Reason != admission.ReasonAttribution {
					t.Fatalf("refused preview left %+v, err %v", c, cerr)
				}
			}
			rows, _ := o.compare.take(h.Add(3*time.Hour), true)
			var refusals []actionlog.Record
			for _, row := range rows {
				if row.Count > 0 && row.Result == actionlog.Refused {
					refusals = append(refusals, row)
				}
			}
			if closeDB {
				if len(refusals) != 0 {
					t.Fatalf("a failed ending counted %+v", refusals)
				}
				return
			}
			if len(refusals) != 1 || refusals[0].Count != 1 || refusals[0].Error != "attribution" || refusals[0].Cause != "target_mismatch" ||
				!refusals[0].Timestamp.Equal(h.Add(time.Hour)) {
				t.Fatalf("refusals = %+v, want one target_mismatch row ending %v", refusals, h.Add(time.Hour))
			}
		})
	}
}
