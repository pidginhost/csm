package admissionowner

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// A retry that is already due at the next turn must not take the place of
// an expired intent the previous batch could not reach.
func TestOwnerRetirementPassesDueRetries(t *testing.T) {
	for _, held := range []bool{false, true} {
		t.Run(fmt.Sprintf("held=%t", held), func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			for i := 1; i <= firewall.MaxBlockBatchMembers+1; i++ {
				retirementAttempt(t, o, p, f, fmt.Sprintf("198.51.100.%d", i), true)
				f.host.advance(10 * time.Second)
				mono.advance(10 * time.Second)
				if err := o.do(o.tick); err != nil {
					t.Fatal(err)
				}
			}
			var intents []admission.Intent
			if err := o.do(func() error {
				var err error
				intents, err = o.ledger.UnresolvedIntents()
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if len(intents) != firewall.MaxBlockBatchMembers+1 {
				t.Fatalf("fixture has %d intents", len(intents))
			}
			tail := intents[len(intents)-1].Action
			wait := firstProbeWait
			if held {
				wait = retireRecheck
				blocks.set(func(b *fakeBlocks) {
					for _, in := range intents[:firewall.MaxBlockBatchMembers] {
						addr, _ := in.Target.Addr()
						b.present[addr.String()] = true
					}
				})
			}
			if err := o.do(func() error {
				rows, err := o.ledger.PendingAudit(int(admission.MaxAuditSlots))
				if err != nil {
					return err
				}
				var acks []admission.AuditAck
				for _, row := range rows {
					if held || row.Attempt.ID == tail {
						acks = append(acks, row.Ack())
					}
				}
				return o.ledger.AckAudit(acks)
			}); err != nil {
				t.Fatal(err)
			}
			f.host.advance(2 * time.Hour)
			mono.advance(2 * time.Hour)
			if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
				t.Fatal(err)
			}
			calls := blocks.retireCalls()
			if len(calls) != 1 || len(calls[0]) != firewall.MaxBlockBatchMembers {
				t.Fatalf("first batch = %+v", calls)
			}
			// Short retries coincide with the normal schedule tick; held
			// retries can also be due after a slow turn or process pause.
			f.host.advance(wait)
			mono.advance(wait)
			if err := o.do(func() error {
				o.schedule()
				a, err := o.ledger.Attempt(tail)
				if err != nil {
					return err
				}
				if !a.Retired {
					t.Error("due retries starved the next expired intent")
				}
				return o.scheduleErr
			}); err != nil {
				t.Fatal(err)
			}
			if st := ledgerStatus(t, o); st.Unresolved.Unknown != firewall.MaxBlockBatchMembers {
				t.Fatalf("retirement bypassed a hold or left the tail: %+v", st.Unresolved)
			}
			for _, batch := range blocks.retireCalls() {
				if len(batch) > firewall.MaxBlockBatchMembers {
					t.Fatalf("retirement batch has %d members", len(batch))
				}
			}
			blocks.set(func(b *fakeBlocks) { clear(b.present) })
			if err := o.do(o.deliverAudit); err != nil {
				t.Fatal(err)
			}
			if !held {
				// A second refusal doubles the ledger wait (M2).
				wait *= 2
			}
			f.host.advance(wait)
			mono.advance(wait)
			if err := o.do(func() error {
				o.schedule()
				if len(o.retireRetry) != 0 || !o.wakeAt.IsZero() || o.scheduleDue {
					t.Errorf("completed retirement retained work: retry %v, wake %v, due %t", o.retireRetry, o.wakeAt, o.scheduleDue)
				}
				return o.scheduleErr
			}); err != nil {
				t.Fatal(err)
			}
			if st := ledgerStatus(t, o); st.Unresolved.Unknown != 0 {
				t.Fatalf("retirement did not wrap around to recovered intents: %+v", st.Unresolved)
			}
		})
	}
}

// A clock read or its durable tick may finish after an unknown expires.
// Time spent obtaining the reading must not postpone its only wake.
func TestOwnerRetirementExpirySurvivesSlowTick(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.91")
	f.host.advance(24*time.Hour - time.Second)
	mono.advance(24*time.Hour - time.Second)
	clock := o.opts.Clock
	slow := true
	setOwnerHook(t, o, &o.opts.Clock, func() (admission.ClockReading, error) {
		reading, err := clock()
		if slow {
			slow = false
			f.host.advance(2 * time.Second)
			mono.advance(2 * time.Second)
		}
		return reading, err
	})
	if err := o.do(func() error {
		o.scheduleDue = true
		o.schedule()
		if o.wakeAt.IsZero() || o.wakeAt.After(mono.read()) {
			t.Errorf("slow tick postponed an elapsed expiry: wake %v, now %v", o.wakeAt, mono.read())
		}
		return o.scheduleErr
	}); err != nil {
		t.Fatal(err)
	}
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if !attemptOf(t, o, c).Retired || len(blocks.retireCalls()) != 1 {
		t.Fatal("expired intent was not retired on the next schedule tick")
	}
}
