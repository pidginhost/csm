package admissionowner

import (
	"maps"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// A sustained attack outlives a candidate that spent its three proven
// failures: repeated reports never reset its retries or age, a report after
// exhaustion queues nothing, and a new observation once the dependency
// recovers is a charged later generation of the same episode (spec 7.1,
// sustained episode after loss).
func TestOwnerSustainedEpisodeAfterExhaustion(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedFull}
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	observed := f.host.now()
	id := observe(t, o, p, f, "192.0.2.10", "offset=1")
	first := candidate(t, o, id)
	for seq := uint32(1); seq <= admission.MaxAttempts; seq++ {
		turn(t, o)
		before := candidate(t, o, id)
		if a := attemptOf(t, o, before); a.State != admission.StateFailed || a.Disposition != admission.DispositionFailed {
			t.Fatalf("failed attempt %d = %+v", seq, a)
		}
		// A repeated report keeps the observation's original timestamp.
		// Changing it would test an evidence conflict instead of placement.
		submitObservation(t, o, p, "192.0.2.10", "offset=1", observed)
		if err := o.do(o.drain); err != nil {
			t.Fatal(err)
		}
		counts := ledgerStatus(t, o).Counters
		if counts.Error != "" {
			t.Fatal(counts.Error)
		}
		refused := map[string]uint64{}
		for _, row := range counts.Rows {
			if row.Event == admission.EventRefused.String() {
				refused[row.Reason] += row.N
			}
		}
		want := map[string]uint64{admission.ReasonExistingEffect.String(): uint64(seq)}
		if seq == admission.MaxAttempts {
			want[admission.ReasonExistingEffect.String()]--
			want[admission.ReasonStale.String()] = 1
		}
		if !maps.Equal(refused, want) {
			t.Fatalf("repeated report %d refusals = %v, want %v", seq, refused, want)
		}
		after := candidate(t, o, id)
		if after.Attempts != seq || after.NotBefore != before.NotBefore || after.AgeOut != first.AgeOut || after.FirstQueued != first.FirstQueued {
			t.Fatalf("a repeated report reset attempt %d: %+v, before %+v", seq, after, before)
		}
		if seq < admission.MaxAttempts {
			wait := admission.RetryBackoff(seq)
			mono.advance(wait)
			f.host.advance(wait)
		}
	}
	if c := candidate(t, o, id); c.State != admission.StateFailed {
		t.Fatalf("after %d failures: %+v", admission.MaxAttempts, c)
	}
	if n := len(queuedCandidates(t, o)); n != 0 {
		t.Fatalf("a report after exhaustion queued %d candidates", n)
	}
	used := ceiling(t, o).General.Used
	if used != uint32(admission.MaxAttempts) {
		t.Fatalf("failed attempts charged %d, want %d", used, admission.MaxAttempts)
	}
	blocks.set(func(b *fakeBlocks) { delete(b.results, "192.0.2.10") })
	mono.advance(time.Minute)
	f.host.advance(time.Minute)
	turn(t, o)
	submitObservation(t, o, p, "192.0.2.10", "offset=2", f.host.now())
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	queued := queuedCandidates(t, o)
	if len(queued) != 1 {
		t.Fatalf("new observation after exhaustion queued %d candidates, want 1", len(queued))
	}
	next, err := queued[0].ID()
	if err != nil {
		t.Fatal(err)
	}
	nc := candidate(t, o, next)
	if nc.Key.Episode != first.Key.Episode || nc.Key.Generation != first.Key.Generation+1 {
		t.Fatalf("the new observation is %+v, want the same episode's next generation of %+v", nc.Key, first.Key)
	}
	mono.advance(batchEvery)
	turn(t, o)
	if c := candidate(t, o, next); c.State != admission.StateVerified || c.Attempts != 1 {
		t.Fatalf("the later generation is %+v", c)
	}
	if got := ceiling(t, o).General.Used; got != used+1 {
		t.Fatalf("general used %d, want %d", got, used+1)
	}
	if a := attemptOf(t, o, candidate(t, o, next)); a.State != admission.StateVerified || a.Disposition != admission.DispositionApplied {
		t.Fatalf("later generation attempt = %+v", a)
	}
}

// One turn's picks mixing members the engine refuses with valid ones
// apply only the valid ones: the refused take no attempt and no charge,
// and the valid ones are charged once each (spec 7.1, batch poisoning).
func TestOwnerMixedRefusalsStayUncharged(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.refuse["192.0.2.10"] = firewall.BlockRefusedInvalid
	blocks.refuse["192.0.2.11"] = firewall.BlockRefusedUnsupported
	o := f.start(executeOptions(f, blocks))
	ids := map[string]admission.CandidateID{}
	for _, addr := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13"} {
		ids[addr], _ = queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
	}
	turn(t, o)
	for _, tc := range []struct {
		addr   string
		state  admission.State
		reason admission.Reason
	}{
		{"192.0.2.10", admission.StateRefused, admission.ReasonInvalid},
		{"192.0.2.11", admission.StateWithheld, admission.ReasonUnsupportedContainment},
	} {
		if c := candidate(t, o, ids[tc.addr]); c.Attempts != 0 || c.State != tc.state || c.Reason != tc.reason || c.Disposition != tc.reason.Disposition() {
			t.Fatalf("refused member %s = %+v", tc.addr, c)
		}
	}
	for _, addr := range []string{"192.0.2.12", "192.0.2.13"} {
		c := candidate(t, o, ids[addr])
		if c.State != admission.StateVerified || c.Attempts != 1 || c.Disposition != admission.DispositionApplied {
			t.Fatalf("valid member %s = %+v", addr, c)
		}
		if a := attemptOf(t, o, c); a.State != admission.StateVerified || a.Disposition != admission.DispositionApplied {
			t.Fatalf("valid member attempt %s = %+v", addr, a)
		}
	}
	if used := ceiling(t, o).General.Used; used != 2 {
		t.Fatalf("general used %d, want 2", used)
	}
}
