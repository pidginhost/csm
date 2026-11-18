package admissionowner

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// refusedCounts are the block refusals the comparison counted, by reason.
func refusedCounts(o *Owner) map[admission.Reason]uint64 {
	o.compare.mu.Lock()
	defer o.compare.mu.Unlock()
	out := map[admission.Reason]uint64{}
	for k, n := range o.compare.counts {
		if k.kind == admission.KindBlockIP && k.decision == decisionRefused {
			out[k.reason] += n
		}
	}
	return out
}

// A live pick that ends refused is counted in the hourly comparison, as a
// refused preview is: at the engine's check before any reservation (a
// protected or allowed address, an invalid, expired or unsupported member)
// and at the reservation itself (work that aged out meanwhile). A pick the
// engine only defers and one an existing block answers are not refusals
// and count nothing.
func TestOwnerCountsLiveRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		refusal firewall.BlockRefusal
		reserve error
		reason  admission.Reason
		want    uint64
	}{
		{"protected address", firewall.BlockRefusedProtected, nil, admission.ReasonProtected, 1},
		{"allowed address", firewall.BlockRefusedAllowed, nil, admission.ReasonProtected, 1},
		{"invalid member", firewall.BlockRefusedInvalid, nil, admission.ReasonInvalid, 1},
		{"expired member", firewall.BlockRefusedExpired, nil, admission.ReasonStale, 1},
		{"unsupported containment", firewall.BlockRefusedUnsupported, nil, admission.ReasonUnsupportedContainment, 1},
		{"aged out at the reservation", "", &admission.Error{Reason: admission.ReasonStale, Detail: "candidate aged out of the queue"}, admission.ReasonStale, 1},
		{"withheld at the reservation", "", &admission.Error{Reason: admission.ReasonCollateral}, admission.ReasonCollateral, 1},
		{"deferred at the reservation", "", &admission.Error{Reason: admission.ReasonStorageShare}, admission.ReasonStorageShare, 0},
		{"full set", firewall.BlockRefusedFull, nil, admission.ReasonSetFull, 0},
		{"pending recovery", firewall.BlockRefusedPending, nil, admission.ReasonPendingRecovery, 0},
		{"existing block", firewall.BlockRefusedExisting, nil, admission.ReasonExistingEffect, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			if tc.refusal != "" {
				blocks.refuse["192.0.2.10"] = tc.refusal
			}
			o := f.start(executeOptions(f, blocks))
			if tc.reserve != nil {
				setOwnerHook(t, o, &reserveLedger, func(*store.AdmissionLedger, admission.CandidateID, admission.Lane, time.Time) (admission.Candidate, admission.AttemptRecord, bool, error) {
					return admission.Candidate{}, admission.AttemptRecord{}, false, tc.reserve
				})
			}
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			turn(t, o)
			c := candidate(t, o, id)
			if c.Reason != tc.reason || c.Attempts != 0 || (tc.want == 1 || tc.refusal == firewall.BlockRefusedExisting) != c.State.Terminal() {
				t.Fatalf("pick = state %s reason %s attempts %d, want reason %s", c.State, c.Reason, c.Attempts, tc.reason)
			}
			counts := refusedCounts(o)
			var total uint64
			for _, n := range counts {
				total += n
			}
			if counts[tc.reason] != tc.want || total != tc.want {
				t.Fatalf("comparison counted refusals %v, want %d as %s", counts, tc.want, tc.reason)
			}
			if _, applies := blocks.calls(); len(applies) != 0 {
				t.Fatalf("a refused pick was applied: %v", applies)
			}
		})
	}
}

// Each caller preserves the candidate's identity and the refusal's cause,
// even when a funnel has already opened a newer comparison hour. A failed
// ending contributes no row, and its retry contributes exactly one.
func TestOwnerCountedRefusalRows(t *testing.T) {
	for _, source := range []string{"engine check", "reservation", "live preview"} {
		t.Run(source, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			comparisonClock(t, f.host.now)
			blocks := newFakeBlocks()
			reason, cause := admission.ReasonAttribution, admission.CauseTargetMismatch
			if source == "engine check" {
				blocks.refuse["192.0.2.10"] = firewall.BlockRefusedProtected
				reason, cause = admission.ReasonProtected, 0
			}
			sink := &actionSink{}
			opts := executeOptions(f, blocks)
			opts.WriteAudit = sink.write
			o := f.start(opts)
			mono := heldMono(t, o)
			refusal := &admission.Error{Reason: reason, Cause: cause}
			kind := admission.KindBlockIP
			switch source {
			case "reservation":
				setOwnerHook(t, o, &reserveLedger, func(*store.AdmissionLedger, admission.CandidateID, admission.Lane, time.Time) (admission.Candidate, admission.AttemptRecord, bool, error) {
					return admission.Candidate{}, admission.AttemptRecord{}, false, refusal
				})
			case "live preview":
				kind = admission.KindChallenge
				setOwnerHook(t, o, &endDryRunLedger, func(*store.AdmissionLedger, admission.CandidateID) (admission.Candidate, bool, error) {
					return admission.Candidate{}, false, refusal
				})
			}
			id, _ := queuedKind(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10", kind)
			before := candidate(t, o, id)
			endingHour := f.host.now().UTC().Truncate(time.Hour)
			// The funnel's later hour must not absorb this ending.
			o.compare.addAt(compareKey{entry: admission.EntryScan, check: "ssh_brute", kind: admission.KindBlockIP, decision: decisionObserve}, endingHour.Add(time.Hour))
			terminate := terminateLedger
			fault := errors.New("fixture ending failure")
			setOwnerHook(t, o, &terminateLedger, func(*store.AdmissionLedger, admission.CandidateID, admission.Reason) (admission.Candidate, error) {
				return admission.Candidate{}, fault
			})
			if err := o.do(o.turn); !errors.Is(err, fault) {
				t.Fatalf("failed ending = %v, want %v", err, fault)
			}
			if c := candidate(t, o, id); !reflect.DeepEqual(c, before) {
				t.Fatalf("failed ending changed candidate: %+v", c)
			}
			if err := o.do(func() error { o.writeComparison(false); return nil }); err != nil {
				t.Fatal(err)
			}
			sink.mu.Lock()
			rows := append([]actionlog.Record(nil), sink.recs...)
			sink.mu.Unlock()
			for _, row := range rows {
				if row.Result == actionlog.Refused && row.Count > 0 {
					t.Fatalf("failed ending counted a refusal: %+v", row)
				}
			}
			setOwnerHook(t, o, &terminateLedger, terminate)
			for range 2 {
				mono.advance(time.Minute)
				turn(t, o)
			}
			if c := candidate(t, o, id); c.State != admission.StateRefused || c.Reason != reason || c.Attempts != 0 {
				t.Fatalf("refused candidate = %+v", c)
			}
			if err := o.do(func() error { o.writeComparison(true); return nil }); err != nil {
				t.Fatal(err)
			}
			sink.mu.Lock()
			rows = append([]actionlog.Record(nil), sink.recs...)
			sink.mu.Unlock()
			var refusals []actionlog.Record
			for _, row := range rows {
				if row.Result == actionlog.Refused && row.Count > 0 {
					refusals = append(refusals, row)
				}
			}
			want := actionlog.Record{
				Timestamp: endingHour.Add(time.Hour), Op: "respond.block_ip", Action: kind.String(),
				Actor: actionlog.Daemon, ActorDetail: before.Entry.String(), Reason: "unknown",
				Result: actionlog.Refused, Error: reason.String(), Count: 1, Epoch: 1,
			}
			if cause != 0 {
				want.Cause = cause.String()
			}
			if !reflect.DeepEqual(refusals, []actionlog.Record{want}) {
				t.Fatalf("refusal rows = %+v, want %+v", refusals, want)
			}
		})
	}
}

// The same engine refusal ends a forecast pick without adding a live
// refusal row. Successful forecasts keep their dry-run prediction row.
func TestOwnerForecastKeepsComparisonRows(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	comparisonClock(t, f.host.now)
	blocks := newFakeBlocks()
	blocks.refuse["192.0.2.10"] = firewall.BlockRefusedProtected
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	refused := observe(t, o, p, f, "192.0.2.10", "offset=1")
	forecast := observe(t, o, p, f, "192.0.2.11", "offset=2")
	turn(t, o)
	if c := candidate(t, o, refused); c.State != admission.StateRefused || c.Reason != admission.ReasonProtected || c.Attempts != 0 {
		t.Fatalf("refused forecast = %+v", c)
	}
	if c := candidate(t, o, forecast); c.State != admission.StateDryRun || c.Attempts != 0 {
		t.Fatalf("successful forecast = %+v", c)
	}
	rows, _ := o.compare.take(f.host.now(), true)
	want := []actionlog.Record{
		{Timestamp: f.host.now().UTC().Truncate(time.Hour).Add(time.Hour), Op: "respond.block_ip", Action: "block_ip", Actor: actionlog.Daemon, ActorDetail: "scan", Reason: "unknown", Result: "queued", Count: 2, Epoch: 1},
		{Timestamp: f.host.now().UTC().Truncate(time.Hour).Add(time.Hour), Op: "respond.block_ip", Action: "block_ip", Actor: actionlog.Daemon, ActorDetail: "scan", Reason: "unknown", Result: actionlog.DryRun, Prediction: admission.PredictCapacityAdmit.String(), Count: 1, Epoch: 1},
	}
	// Rows in an hour have no ordering contract.
	if len(rows) != len(want) {
		t.Fatalf("forecast rows = %+v, want %+v", rows, want)
	}
	for _, expected := range want {
		found := false
		for _, row := range rows {
			found = found || reflect.DeepEqual(row, expected)
		}
		if !found {
			t.Fatalf("forecast rows = %+v, missing %+v", rows, expected)
		}
	}
}

// A refusal that cannot be written counts nothing: the pick is still
// queued and the next turn ends and counts it once.
func TestOwnerCountsALiveRefusalOnlyOnceItCommits(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.refuse["192.0.2.10"] = firewall.BlockRefusedProtected
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	terminate := terminateLedger
	setOwnerHook(t, o, &terminateLedger, func(*store.AdmissionLedger, admission.CandidateID, admission.Reason) (admission.Candidate, error) {
		return admission.Candidate{}, errors.New("fixture write failure")
	})
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err == nil {
		t.Fatal("a failed ending did not fail the turn")
	}
	if c := candidate(t, o, id); c.State != admission.StateQueued || len(refusedCounts(o)) != 0 {
		t.Fatalf("after a failed ending: state %s, refusals %v", c.State, refusedCounts(o))
	}
	setOwnerHook(t, o, &terminateLedger, terminate)
	for range 2 {
		mono.advance(time.Minute)
		turn(t, o)
	}
	if n := refusedCounts(o)[admission.ReasonProtected]; n != 1 {
		t.Fatalf("comparison counted %d protected refusals over two turns, want 1", n)
	}
}

// A refusal that committed stays counted when a later pick of the same
// turn fails to end: the failed turn counts the one that committed and no
// more, and the retry ends and counts only the pick still queued.
func TestOwnerCountsCommittedRefusalAcrossLaterFailure(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	addrs := []string{"192.0.2.10", "192.0.2.11"}
	for _, addr := range addrs {
		blocks.refuse[addr] = firewall.BlockRefusedProtected
	}
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	terminate := terminateLedger
	calls := 0
	setOwnerHook(t, o, &terminateLedger, func(l *store.AdmissionLedger, id admission.CandidateID, r admission.Reason) (admission.Candidate, error) {
		if calls++; calls == 2 {
			return admission.Candidate{}, errors.New("fixture write failure")
		}
		return terminate(l, id, r)
	})
	var ids []admission.CandidateID
	for _, addr := range addrs {
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
		ids = append(ids, id)
	}
	states := func() (terminal, queued int) {
		for _, id := range ids {
			switch c := candidate(t, o, id); {
			case c.Attempts != 0:
				t.Fatalf("a refused pick made an attempt: %+v", c)
			case c.State.Terminal():
				terminal++
			case c.State == admission.StateQueued:
				queued++
			}
		}
		return terminal, queued
	}
	if err := o.do(o.turn); err == nil {
		t.Fatal("the failed ending did not fail the turn")
	}
	if terminal, queued := states(); terminal != 1 || queued != 1 || refusedCounts(o)[admission.ReasonProtected] != 1 {
		t.Fatalf("after the failed turn: %d terminal, %d queued, refusals %v; want one of each", terminal, queued, refusedCounts(o))
	}
	setOwnerHook(t, o, &terminateLedger, terminate)
	for range 2 {
		mono.advance(time.Minute)
		turn(t, o)
	}
	if terminal, _ := states(); terminal != 2 || refusedCounts(o)[admission.ReasonProtected] != 2 || len(refusedCounts(o)) != 1 {
		t.Fatalf("after the retry: %d terminal, refusals %v; want two protected refusals", terminal, refusedCounts(o))
	}
	if _, applies := blocks.calls(); len(applies) != 0 {
		t.Fatalf("a refused pick was applied: %v", applies)
	}
}
