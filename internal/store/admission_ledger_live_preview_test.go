package store

import (
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
)

// On a live ledger only block_ip work runs. A preview of any other kind
// spends nothing there, so the schedule serves it without a lane's ceiling
// budget or history allowance and leaves both to the work that runs.
// Before the live start a preview is charged as live work would be, and
// competes with it for the same budget.
func TestAdmissionLedgerScheduleServesPreviewKindsOutsideTheLanes(t *testing.T) {
	for _, started := range []bool{false, true} {
		t.Run(fmt.Sprintf("started=%t", started), func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			if started {
				if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
					t.Fatal(err)
				}
			}
			queue := func(addr string, kind admission.Kind) admission.CandidateID {
				req := f.request(addr, f.published(evidenceSpec{target: addr, cursor: "cursor=" + addr}))
				req.Kind = kind
				_, id := f.enqueue(req)
				return id
			}
			promote := queue("192.0.2.41", admission.KindPromote)
			challenge := queue("192.0.2.42", admission.KindChallenge)
			block := queue("192.0.2.43", admission.KindBlockIP)
			f.leaveCeilingCredit(1, 0)
			picked := map[admission.CandidateID]admission.Pick{}
			for _, p := range f.schedule(fullSchedule) {
				picked[p.ID] = p
			}
			if p, ok := picked[challenge]; !ok || p.Cost != 0 || (p.Bytes == 0) != started {
				t.Fatalf("challenge pick = %+v, picked %t", p, ok)
			}
			if !started {
				// One unit of credit serves the promotion or the block,
				// and the other waits for the ceiling.
				waiting := block
				if _, ok := picked[block]; ok {
					waiting = promote
				}
				if len(picked) != 2 || f.candidateOf(waiting).Reason != admission.ReasonCeiling {
					t.Fatalf("picks before the live start = %+v, waiting %+v", picked, f.candidateOf(waiting))
				}
				return
			}
			if p, ok := picked[promote]; !ok || p.Cost != 0 || p.Bytes != 0 {
				t.Fatalf("promotion pick on a live ledger = %+v, picked %t", p, ok)
			}
			if p, ok := picked[block]; !ok || p.Cost != 1 || p.Bytes == 0 {
				t.Fatalf("block pick on a live ledger = %+v, picked %t", p, ok)
			}
			for _, id := range []admission.CandidateID{promote, challenge, block} {
				if c := f.candidateOf(id); c.State != admission.StateQueued || c.Reason != 0 {
					t.Fatalf("a pick was deferred: %+v", c)
				}
			}
		})
	}
}

// Work of a kind a live ledger only previews keeps no capacity wait across
// the live start. Whatever deferred it before, with the ceiling and the
// history allowance both spent and with or without a full set, it is due
// at once, selected at no cost, and ends without a charge; once it has
// ended nothing keeps a wake alive.
func TestAdmissionLedgerStartedPreviewWakeAndDeferrals(t *testing.T) {
	for _, reason := range []admission.Reason{admission.ReasonCeiling, admission.ReasonSetFull, admission.ReasonStorageShare} {
		for _, set := range []*admission.SetOccupancy{nil, {Limit: 5, Unclaimed: 5}} {
			t.Run(fmt.Sprintf("%s/full set=%t", reason, set != nil), func(t *testing.T) {
				f := newLedgerFixture(t)
				f.begin()
				var ids []admission.CandidateID
				for addr, kind := range map[string]admission.Kind{"192.0.2.51": admission.KindChallenge, "192.0.2.52": admission.KindPromote} {
					req := f.request(addr, f.published(evidenceSpec{target: addr, cursor: "cursor=" + addr}))
					req.Kind = kind
					_, id := f.enqueue(req)
					if _, err := f.l.Defer(id, reason); err != nil {
						t.Fatal(err)
					}
					ids = append(ids, id)
				}
				if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
					t.Fatal(err)
				}
				f.leaveCeilingCredit(0, 0)
				f.adjustStorage(func(s *admission.StorageState) { s.General.Credit, s.Reserved.Credit = 0, 0 })
				f.l.SetOccupants(set)
				if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall) {
					t.Fatalf("wake with previews queued = %v %v %v, want now", wake, ok, err)
				}
				picks := f.schedule(fullSchedule)
				if len(picks) != 2 {
					t.Fatalf("picks = %+v, want both previews", picks)
				}
				for _, p := range picks {
					if p.Cost != 0 || p.Bytes != 0 {
						t.Fatalf("preview pick takes room: %+v", p)
					}
				}
				for _, id := range ids {
					// A set_full label stays while the ledger has no set to
					// judge it by; it must not stop the selection.
					if c := f.candidateOf(id); c.State != admission.StateQueued || (c.Reason != 0 && (c.Reason != admission.ReasonSetFull || set != nil)) {
						t.Fatalf("picked preview = %s/%s", c.State, c.Reason)
					}
					c, changed, err := f.l.EndDryRun(id)
					if err != nil || !changed || c.State != admission.StateDryRun || c.Reason != 0 || c.Attempts != 0 {
						t.Fatalf("ending the preview = %+v, changed %t, %v", c, changed, err)
					}
				}
				if len(f.charges()) != 0 || f.ceilingState().General.Used != 0 {
					t.Fatalf("previews were charged: %+v", f.charges())
				}
				if wake, ok, err := f.l.NextWake(nil); err != nil || ok {
					t.Fatalf("wake after the previews ended = %v %v %v, want none", wake, ok, err)
				}
			})
		}
	}
}
