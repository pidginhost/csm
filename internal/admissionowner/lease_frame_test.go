package admissionowner

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// After the wall clock is set back the engine's lease clock stays ahead
// of it. A new block's expiry is set on the engine's clock, so the kernel
// holds it for its whole lifetime rather than the lifetime less the step,
// and a short block is not refused as already expired (spec 5.4, 5.5). A
// retry keeps the first expiry.
func TestOwnerSetsExpiriesOnTheEngineLease(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	const lead = 30 * time.Hour
	blocks.set(func(b *fakeBlocks) {
		b.lease = func() time.Time { return f.host.now().Add(lead) }
		b.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed}
	})
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	lease := f.host.now().Add(lead)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	want := lease.Add(24 * time.Hour)
	_, applies := blocks.calls()
	if len(applies) != 1 || !applies[0][0].ExpiresAt.Equal(want) {
		t.Fatalf("first attempt applies = %+v, want an expiry of %v on the engine's clock", applies, want)
	}
	if c := candidate(t, o, id); !c.ExpiresAt.Equal(want) {
		t.Fatalf("ledger expiry = %v, want %v", c.ExpiresAt, want)
	}
	blocks.set(func(b *fakeBlocks) { delete(b.results, "192.0.2.10") })
	mono.advance(admission.RetryBackoff(1) + time.Second)
	f.host.advance(admission.RetryBackoff(1) + time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	_, applies = blocks.calls()
	if len(applies) != 2 || !applies[1][0].ExpiresAt.Equal(want) {
		t.Fatalf("retry applies = %+v, want the first expiry %v kept", applies, want)
	}
	if c := candidate(t, o, id); c.State != admission.StateVerified || !c.ExpiresAt.Equal(want) {
		t.Fatalf("candidate = %+v", c)
	}
}

// All new members use one lease reading, even when reads would advance.
// The real ledger must accept short expiries ahead of its admission time.
func TestOwnerLeaseFrameUsesOneReadingPerBatch(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	lease := f.host.now().Add(30 * time.Hour)
	reads := 0
	blocks.lease = func() time.Time {
		reads++
		return lease.Add(time.Duration(reads-1) * time.Second)
	}
	opts := executeOptions(f, blocks)
	opts.Expiry = func(admission.Candidate) time.Duration { return 30 * time.Second }
	o := f.start(opts)
	heldMono(t, o)
	ids := make([]admission.CandidateID, 0, 2)
	for _, ip := range []string{"192.0.2.10", "192.0.2.11"} {
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, ip)
		ids = append(ids, id)
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	checks, applies := blocks.calls()
	if reads != 1 || len(checks) != 1 || len(checks[0]) != 2 || len(applies) != 1 || len(applies[0]) != 2 {
		t.Fatalf("lease reads=%d checks=%+v applies=%+v", reads, checks, applies)
	}
	want := lease.Add(30 * time.Second)
	for _, batch := range [][]firewall.BlockMember{checks[0], applies[0]} {
		for _, member := range batch {
			if !member.ExpiresAt.Equal(want) {
				t.Fatalf("member expiry = %v, want %v", member.ExpiresAt, want)
			}
		}
	}
	for _, id := range ids {
		c := candidate(t, o, id)
		if c.State != admission.StateVerified || c.Attempts != 1 || !c.ExpiresAt.Equal(want) {
			t.Fatalf("lease expiry failed the ledger reservation: %+v", c)
		}
	}
}

// Previews use the admission clock and never require an engine lease.
func TestOwnerLeaseFramePreviewUsesAdmissionTime(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(previewOptions(f))
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	want := f.host.now().Add(24 * time.Hour)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, id); c.State != admission.StateObserved || !c.ExpiresAt.Equal(want) {
		t.Fatalf("preview expiry changed clocks: %+v, want %v", c, want)
	}
}
