package store

import (
	"fmt"
	"testing"
	"time"

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

// A dry-run selection on a live ledger serves a challenge whatever the
// history allowance holds, and wakes for it at once: its preview ends
// without history there. Before the live start the preview is a charged
// attempt, so a challenge the allowance cannot pay for is passed over and
// the wake waits for the allowance.
func TestAdmissionLedgerPreviewSelectionNeedsNoHistoryOnceLive(t *testing.T) {
	for _, pressure := range []string{"credit", "allowance", "recovery"} {
		for _, direct := range []bool{false, true} {
			for _, started := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/direct=%t/started=%t", pressure, direct, started), func(t *testing.T) {
					f := newLedgerFixture(t)
					f.begin()
					spec := evidenceSpec{target: "192.0.2.61", cursor: "offset=61"}
					if direct {
						spec.producer, spec.check, spec.severity = f.mail, "mail_takeover", admission.SeverityCritical
					}
					req := f.request("192.0.2.61", f.published(spec))
					req.Kind = admission.KindChallenge
					_, id := f.enqueue(req)
					if started {
						if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
							t.Fatal(err)
						}
					}
					f.adjustStorage(func(s *admission.StorageState) {
						switch pressure {
						case "credit":
							s.General.Credit, s.Reserved.Credit = 0, 0
						case "allowance":
							s.General.Used, s.Reserved.Used = admission.HistoryLanes()
						case "recovery":
							leaveRecoveryRoom(s, 0)
						}
					})
					before := f.storageState()
					wake, ok, err := f.l.PreviewWake(nil)
					if err != nil {
						t.Fatal(err)
					}
					picks, err := f.l.SchedulePreview(nil)
					if err != nil {
						t.Fatal(err)
					}
					if got := f.storageState(); got != before {
						t.Fatalf("selection changed history: %+v, was %+v", got, before)
					}
					if !started {
						if len(picks) != 0 || !ok || !wake.After(f.wall) {
							t.Fatalf("before the live start: picks %+v, wake %v %t; want the challenge to wait for history", picks, wake, ok)
						}
						return
					}
					if len(picks) != 1 || picks[0].ID != id || !ok || !wake.Equal(f.wall) {
						t.Fatalf("on a live ledger: picks %+v, wake %v %t; want the challenge selected now", picks, wake, ok)
					}
					wantLane := admission.LaneGeneral
					if direct {
						wantLane = admission.LaneDirect
					}
					if picks[0].Lane != wantLane || picks[0].Bytes != 0 || picks[0].Cost != 1 {
						t.Fatalf("uncharged preview pick = %+v, want lane %s and one fair unit", picks[0], wantLane)
					}
					if c, changed, endErr := f.l.EndDryRun(id); endErr != nil || !changed || c.State != admission.StateDryRun {
						t.Fatalf("ending the selected challenge = %+v, %t, %v", c, changed, endErr)
					}
					if wake, ok, err = f.l.PreviewWake(nil); err != nil || ok {
						t.Fatalf("wake after the challenge ended = %v %t %v, want none", wake, ok, err)
					}
				})
			}
		}
	}
}

// A challenge on a live ledger still waits for what a preview must not
// pass: its retry backoff, a target an unresolved attempt holds, and an
// answer still pending. Each wake is the moment that wait can end, never
// now, and the challenge is selected at once when the wait is over.
func TestAdmissionLedgerStartedChallengePreviewWaits(t *testing.T) {
	started := func(t *testing.T) *ledgerFixture {
		f := newLedgerFixture(t)
		f.begin()
		if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
			t.Fatal(err)
		}
		return f
	}
	challenge := func(f *ledgerFixture, addr string) admission.CandidateID {
		req := f.request(addr, f.published(evidenceSpec{target: addr, cursor: "challenge=" + addr}))
		req.Kind = admission.KindChallenge
		_, id := f.enqueue(req)
		return id
	}
	waits := func(t *testing.T, f *ledgerFixture, answers map[admission.CandidateID]admission.Answer, want time.Time) {
		t.Helper()
		f.adjustStorage(func(s *admission.StorageState) { leaveRecoveryRoom(s, 0) })
		if picks, err := f.l.SchedulePreview(answers); err != nil || len(picks) != 0 {
			t.Fatalf("selection while waiting = %+v, %v; want none", picks, err)
		}
		if wake, ok, err := f.l.PreviewWake(answers); err != nil || !ok || !wake.Equal(want) || !wake.After(f.wall) {
			t.Fatalf("wake while waiting = %v %t %v, want %v", wake, ok, err, want)
		}
	}
	served := func(t *testing.T, f *ledgerFixture, id admission.CandidateID) {
		t.Helper()
		// Retiring a held attempt frees recovery room. Keep that room
		// exhausted so only the readiness change can release the preview.
		f.adjustStorage(func(s *admission.StorageState) { leaveRecoveryRoom(s, 0) })
		charges := len(f.charges())
		if wake, ok, err := f.l.PreviewWake(nil); err != nil || !ok || !wake.Equal(f.wall) {
			t.Fatalf("wake once the wait is over = %v %t %v, want now", wake, ok, err)
		}
		if picks, err := f.l.SchedulePreview(nil); err != nil || len(picks) != 1 || picks[0].ID != id {
			t.Fatalf("selection once the wait is over = %+v, %v; want only the challenge", picks, err)
		}
		if got := len(f.charges()); got != charges {
			t.Fatalf("the selection changed the charges: %d, was %d", got, charges)
		}
	}
	t.Run("retry backoff", func(t *testing.T) {
		f := started(t)
		id := challenge(f, "192.0.2.71")
		_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
			t.Fatal(err)
		}
		c := f.candidateOf(id)
		if c.State != admission.StateQueued || c.Attempts != 1 || !c.NotBefore.After(f.wall) {
			t.Fatalf("fixture: failed attempt left %s with %d attempts, due %v", c.State, c.Attempts, c.NotBefore)
		}
		waits(t, f, nil, c.NotBefore)
		f.tickAt(c.NotBefore)
		served(t, f, id)
	})
	t.Run("held target", func(t *testing.T) {
		f := started(t)
		expires := f.wall.Add(time.Minute)
		u := f.unknownAt("192.0.2.72", expires)
		f.ackAll()
		f.nextGeneration()
		id := challenge(f, "192.0.2.72")
		c := f.candidateOf(id)
		if !c.AgeOut.After(expires) {
			t.Fatalf("fixture: the challenge ages out at %v, not after the block's expiry %v", c.AgeOut, expires)
		}
		waits(t, f, nil, c.AgeOut)
		f.tickAt(expires)
		if _, _, changed, err := f.l.RetireUnproven(u.Attempt.ID); err != nil || !changed {
			t.Fatalf("retiring the unknown attempt = %t, %v", changed, err)
		}
		served(t, f, id)
	})
	t.Run("pending answer", func(t *testing.T) {
		f := started(t)
		id := challenge(f, "192.0.2.73")
		waits(t, f, pendingSet(id), f.candidateOf(id).AgeOut)
		served(t, f, id)
	})
}
