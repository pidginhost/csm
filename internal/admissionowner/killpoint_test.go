package admissionowner

import (
	"reflect"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// killPoint is what a kill point panics with: the step stops where it is,
// as a process killed there would.
type killPoint struct{}

// crash runs step on the owner goroutine until a kill point stops it, then
// halts the owner without its clean shutdown. Nothing the turn held in
// memory is written, as after a kill; Stop would retry pending outcomes.
func crash(t *testing.T, o *Owner, step func() error) {
	t.Helper()
	stopped := false
	err := o.do(func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(killPoint); !ok {
					panic(r)
				}
				stopped = true
			}
		}()
		return step()
	})
	if err != nil || !stopped {
		t.Fatalf("kill point not reached: stopped %t, %v", stopped, err)
	}
	o.halt(false)
}

// killReserve stops the turn before its nth reservation.
func killReserve(n int) func(*testing.T, *Owner, *fakeBlocks) {
	return func(t *testing.T, o *Owner, _ *fakeBlocks) {
		reserve, calls := reserveLedger, 0
		setOwnerHook(t, o, &reserveLedger, func(l *store.AdmissionLedger, id admission.CandidateID, lane admission.Lane, expires time.Time) (admission.Candidate, admission.AttemptRecord, bool, error) {
			if calls++; calls == n {
				panic(killPoint{})
			}
			return reserve(l, id, lane, expires)
		})
	}
}

// killExecute stops the turn just before the batch is recorded as running,
// or just after when committed is set.
func killExecute(committed bool) func(*testing.T, *Owner, *fakeBlocks) {
	return func(t *testing.T, o *Owner, _ *fakeBlocks) {
		execute, fired := executeLedger, false
		setOwnerHook(t, o, &executeLedger, func(l *store.AdmissionLedger, ids []admission.ActionID) ([]admission.Intent, bool, error) {
			if fired {
				return execute(l, ids)
			}
			fired = true
			if committed {
				if _, granted, err := execute(l, ids); err != nil || !granted {
					t.Errorf("recording the batch as running = %t, %v", granted, err)
				}
			}
			panic(killPoint{})
		})
	}
}

// killEngine stops the turn inside the engine, once its batch has results.
func killEngine(_ *testing.T, _ *Owner, blocks *fakeBlocks) {
	blocks.set(func(b *fakeBlocks) {
		b.afterApply = func(b *fakeBlocks) {
			b.afterApply = nil
			panic(killPoint{})
		}
	})
}

// killFinish stops the turn at its nth outcome write: before it, or just
// after when committed is set.
func killFinish(n int, committed bool) func(*testing.T, *Owner, *fakeBlocks) {
	return func(t *testing.T, o *Owner, _ *fakeBlocks) {
		finish, calls := finishLedger, 0
		setOwnerHook(t, o, &finishLedger, func(l *store.AdmissionLedger, id admission.ActionID, d admission.Disposition) (admission.Candidate, admission.AttemptRecord, error) {
			if calls++; calls != n {
				return finish(l, id, d)
			}
			if committed {
				if _, _, err := finish(l, id, d); err != nil {
					t.Errorf("finishing %s: %v", id, err)
				}
			}
			panic(killPoint{})
		})
	}
}

// Non-applied outcomes have different retry and retirement paths.
func killResultFinish(effect firewall.BlockEffect, n int) func(*testing.T, *Owner, *fakeBlocks) {
	return func(t *testing.T, o *Owner, blocks *fakeBlocks) {
		blocks.set(func(b *fakeBlocks) {
			for _, ip := range []string{"192.0.2.20", "192.0.2.21"} {
				b.results[ip] = firewall.BlockResult{Effect: effect}
			}
		})
		killFinish(n, true)(t, o, blocks)
	}
}

// Kill points of the owner's turn (spec 5.4, 5.5; design P6, P7): a batch
// of two block picks is stopped at each step and the owner restarted on
// the same ledger. The restart settles what was left reserved as failed
// and what was left running as unknown. It sends nothing to the engine
// again, hands the consumers only the outcomes that were finished
// applied, and gives the startup gate the same answers. A failed member
// retries as its next attempt; each unknown one holds its address until
// its expiry, and then retires once the engine finds nothing of it. A
// further restart changes nothing.
func TestOwnerConvergesAfterAKillInTheTurn(t *testing.T) {
	type outcome struct{ failed, unknown, verified int }
	for _, tc := range []struct {
		name string
		arm  func(*testing.T, *Owner, *fakeBlocks)
		// sent is whether the killed turn reached the engine.
		sent bool
		want outcome
	}{
		{"before the first reservation", killReserve(1), false, outcome{}},
		{"between reservations", killReserve(2), false, outcome{failed: 1}},
		{"before running", killExecute(false), false, outcome{failed: 2}},
		{"after running", killExecute(true), false, outcome{unknown: 2}},
		{"inside the engine", killEngine, true, outcome{unknown: 2}},
		{"before the first finish", killFinish(1, false), true, outcome{unknown: 2}},
		{"after the first finish", killFinish(1, true), true, outcome{unknown: 1, verified: 1}},
		{"after the last finish", killFinish(2, true), true, outcome{verified: 2}},
		{"after the first failed finish", killResultFinish(firewall.BlockFailed, 1), true, outcome{failed: 1, unknown: 1}},
		{"after the last failed finish", killResultFinish(firewall.BlockFailed, 2), true, outcome{failed: 2}},
		{"after the first unknown finish", killResultFinish(firewall.BlockUnknown, 1), true, outcome{unknown: 2}},
		{"after the last unknown finish", killResultFinish(firewall.BlockUnknown, 2), true, outcome{unknown: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := withTestRegistry(t)
				f := newOwnerFixture(t)
				blocks := newFakeBlocks()
				consumer := &appliedSink{}
				opts := executeOptions(f, blocks)
				opts.Applied = consumer.consume
				o := f.start(opts)
				mono := heldMono(t, o)
				picks := map[admission.CandidateID]string{}
				var pickOrder []admission.CandidateID
				for _, addr := range []string{"192.0.2.20", "192.0.2.21"} {
					id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
					picks[id] = addr
					pickOrder = append(pickOrder, id)
				}
				// Slow CI must not let default timers execute the queued batch.
				time.Sleep(2 * time.Second)
				synctest.Wait()
				for _, id := range pickOrder {
					if c := candidate(t, o, id); c.State != admission.StateQueued || c.Attempts != 0 {
						t.Fatalf("fixture timers ran queued work: %+v", c)
					}
				}
				beforeCeiling := ceiling(t, o)
				tc.arm(t, o, blocks)
				crash(t, o, o.turn)
				if _, applies := blocks.calls(); len(applies) != map[bool]int{true: 1}[tc.sent] {
					t.Fatalf("the killed turn sent %d batches; want sent %t", len(applies), tc.sent)
				}

				_, firstBatches := blocks.calls()
				firstSent := map[string]int{}
				for _, batch := range firstBatches {
					for _, m := range batch {
						firstSent[m.Action]++
					}
				}
				killedCeiling, ceilingErr := o.ledger.Ceiling()
				if ceilingErr != nil {
					t.Fatal(ceilingErr)
				}
				o = f.start(opts)
				var got outcome
				var all, failed, unknown, verified, held []string
				beforeRetry := map[admission.CandidateID]admission.Candidate{}
				for _, id := range pickOrder {
					addr := picks[id]
					c := candidate(t, o, id)
					beforeRetry[id] = c
					if c.Attempts == 0 {
						if c.State != admission.StateQueued {
							t.Fatalf("an unreserved pick = %+v", c)
						}
						continue
					}
					if c.Attempts != 1 {
						t.Fatalf("restart changed the first attempt count: %+v", c)
					}
					at := attemptOf(t, o, c)
					name := string(at.Attempt.ID)
					all = append(all, name)
					switch {
					case at.State == admission.StateFailed && c.State == admission.StateQueued:
						got.failed++
						failed = append(failed, name)
						if !c.NotBefore.Equal(at.Finished.Add(admission.RetryBackoff(1))) {
							t.Fatalf("failed attempt lost its retry backoff: %+v, %+v", c, at)
						}
					case at.State == admission.StateUnknown && c.State == admission.StateUnknown && !at.Retired:
						got.unknown++
						unknown = append(unknown, name)
						held = append(held, addr)
					case at.State == admission.StateVerified && c.State == admission.StateVerified:
						got.verified++
						verified = append(verified, name)
					default:
						t.Fatalf("after the restart pick %s = %+v, attempt %+v", id, c, at)
					}
				}
				if got != tc.want {
					t.Fatalf("after the restart %+v; want %+v", got, tc.want)
				}
				afterCeiling := ceiling(t, o)
				wantCharged := tc.want.failed + tc.want.unknown + tc.want.verified
				used := func(c admission.CeilingState) int { return int(c.General.Used + c.Reserved.Used) }
				if used(afterCeiling)-used(beforeCeiling) != wantCharged || afterCeiling != killedCeiling {
					t.Fatalf("restart changed charges: before %+v, killed %+v, restarted %+v; want %d retained", beforeCeiling, killedCeiling, afterCeiling, wantCharged)
				}
				if spent := int(beforeCeiling.General.Units()+beforeCeiling.Reserved.Units()) - int(afterCeiling.General.Units()+afterCeiling.Reserved.Units()); spent != wantCharged {
					t.Fatalf("restart retained %d pacing debits, want %d", spent, wantCharged)
				}
				wantRetry := 2 - tc.want.unknown - tc.want.verified
				queued := 0
				for _, c := range beforeRetry {
					if c.State == admission.StateQueued {
						queued++
					}
				}
				if queued != wantRetry {
					t.Fatalf("restart left %d retryable picks; want %d", queued, wantRetry)
				}
				if st := ledgerStatus(t, o).Unresolved; st.Running != 0 || st.Unknown != len(unknown) {
					t.Fatalf("unresolved after the restart = %+v; want nothing running and %d unknown", st, len(unknown))
				}
				// The startup gate holds back every row of an attempt not
				// finished applied and removes the rows of failed ones.
				unproven, err := store.ReadUnprovenBlockActions(f.db, all)
				if err != nil || !sameNames(unproven, append(slices.Clone(failed), unknown...)) {
					t.Fatalf("unproven = %v, %v; want %v and %v", unproven, err, failed, unknown)
				}
				settled, err := store.ReadSettledBlockActions(f.db, all)
				if err != nil || !sameNames(settled, failed) {
					t.Fatalf("settled = %v, %v; want %v", settled, err, failed)
				}
				if err = o.do(o.deliverAudit); err != nil {
					t.Fatal(err)
				}
				var consumed []string
				for _, batch := range consumer.seen() {
					for _, row := range batch {
						consumed = append(consumed, string(row.Attempt.ID))
					}
				}
				if !sameNames(consumed, verified) {
					t.Fatalf("consumers saw %v; want only the finished applied %v", consumed, verified)
				}

				// A failed member's retry is its next attempt; nothing sent
				// before the kill is sent again. Until its expiry an unknown
				// one holds its address: other work there waits.
				var overlaps []admission.CandidateID
				for _, addr := range held {
					id, _ := queuedKind(t, o, p, f.host, admission.SeverityHigh, addr, admission.KindPromote)
					overlaps = append(overlaps, id)
				}
				mono.advance(admission.RetryBackoff(1) + time.Second)
				f.host.advance(admission.RetryBackoff(1) + time.Second)
				turn(t, o)
				for _, id := range overlaps {
					if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != admission.ReasonPendingRecovery || c.Attempts != 0 {
						t.Fatalf("an unknown attempt released its address before its expiry: %+v", c)
					}
				}
				if calls := blocks.retireCalls(); len(calls) != 0 {
					t.Fatalf("retirement before the expiry: %v", calls)
				}
				_, applies := blocks.calls()
				sent := map[string]int{}
				sentExpiry := map[string]time.Time{}
				for _, batch := range applies {
					for _, m := range batch {
						sent[m.Action]++
						sentExpiry[m.Action] = m.ExpiresAt
					}
				}
				for name, n := range sent {
					if n != 1 {
						t.Fatalf("%s reached the engine %d times", name, n)
					}
				}
				for _, name := range failed {
					if sent[name] != firstSent[name] {
						t.Fatalf("a failed attempt reached the engine again: %s", name)
					}
				}
				retried := 0
				for _, id := range pickOrder {
					prior := beforeRetry[id]
					if prior.State != admission.StateQueued {
						continue
					}
					retried++
					c := candidate(t, o, id)
					a := attemptOf(t, o, c)
					want, attemptErr := admission.NewAttempt(id, prior.Attempts+1)
					if attemptErr != nil || c.Attempts != prior.Attempts+1 || a.Attempt != want || sent[string(want.ID)] != 1 {
						t.Fatalf("retry of %s = %+v, %+v, %v; want next attempt %+v sent once", id, c, a, attemptErr, want)
					}
					if !sentExpiry[string(want.ID)].Equal(c.ExpiresAt) || (prior.Attempts > 0 && !c.ExpiresAt.Equal(prior.ExpiresAt)) {
						t.Fatalf("retry extended the original expiry: %v to %v", prior.ExpiresAt, c.ExpiresAt)
					}
				}
				if retried != wantRetry {
					t.Fatalf("checked %d retries; want %d", retried, wantRetry)
				}
				if retryCeiling := ceiling(t, o); used(retryCeiling)-used(beforeCeiling) != wantCharged+wantRetry {
					t.Fatalf("retries lost charges: %+v; want %d original and new charges", retryCeiling, wantCharged+wantRetry)
				}
				// Each pick never reserved or settled failed runs once now; the
				// killed attempts count only if they reached the engine.
				if want := 2 - len(all) + len(failed) + len(firstSent); len(sent) != want {
					t.Fatalf("the engine saw %d attempts; want %d", len(sent), want)
				}

				// Once the expiry passes and the engine finds nothing, each
				// unknown retires; the gate then removes its row.
				mono.advance(25 * time.Hour)
				f.host.advance(25 * time.Hour)
				turn(t, o)
				var retired []string
				for _, call := range blocks.retireCalls() {
					for _, m := range call {
						retired = append(retired, m.Action)
					}
				}
				if !sameNames(retired, unknown) {
					t.Fatalf("the engine was asked to retire %v; want %v", retired, unknown)
				}
				if settled, err = store.ReadSettledBlockActions(f.db, unknown); err != nil || !sameNames(settled, unknown) {
					t.Fatalf("retired unknowns settled = %v, %v; want %v", settled, err, unknown)
				}
				if st := ledgerStatus(t, o).Unresolved; st.Running != 0 || st.Unknown != 0 {
					t.Fatalf("unresolved after retirement = %+v", st)
				}

				if err := o.do(o.deliverAudit); err != nil {
					t.Fatal(err)
				}
				consumedBefore := len(consumer.seen())
				stable := map[admission.CandidateID]admission.Candidate{}
				for id := range picks {
					stable[id] = candidate(t, o, id)
				}
				_, applies = blocks.calls()
				o.halt(false)
				o = f.start(opts)
				turn(t, o)
				if err := o.do(o.deliverAudit); err != nil {
					t.Fatal(err)
				}
				if len(consumer.seen()) != consumedBefore {
					t.Fatal("a further restart redelivered acknowledged outcomes")
				}
				for id, before := range stable {
					if after := candidate(t, o, id); !reflect.DeepEqual(after, before) {
						t.Fatalf("a further restart changed %s: before %+v, after %+v", id, before, after)
					}
				}
				if _, again := blocks.calls(); len(again) != len(applies) {
					t.Fatalf("a further restart sent %d more batches", len(again)-len(applies))
				}
				if calls := blocks.retireCalls(); len(calls) != map[bool]int{true: 1}[len(unknown) > 0] {
					t.Fatalf("a further restart asked the engine to retire again: %v", calls)
				}
			})
		})
	}
}

// Kill points of audit delivery (spec 5.5, design P14): a kill after the
// action log write, or after the consumers saw a verified block's row,
// acknowledges nothing. Restart redelivers the same identity until its
// acknowledgement. A kill after acknowledgement redelivers nothing.
func TestOwnerRedeliversAppliedRowsAfterAKill(t *testing.T) {
	for _, after := range []string{"before the action log write", "the action log write", "the consumers", "the acknowledgement"} {
		t.Run(after, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := withTestRegistry(t)
				f := newOwnerFixture(t)
				blocks := newFakeBlocks()
				sink, consumer := &auditSink{}, &appliedSink{}
				armed := true
				opts := executeOptions(f, blocks)
				opts.WriteAudit = func(rs []actionlog.Record) error {
					if armed && after == "before the action log write" {
						armed = false
						panic(killPoint{})
					}
					err := sink.write(rs)
					if armed && after == "the action log write" {
						armed = false
						panic(killPoint{})
					}
					return err
				}
				opts.Applied = func(rows []admission.AuditRow) error {
					err := consumer.consume(rows)
					if armed && after == "the consumers" {
						armed = false
						panic(killPoint{})
					}
					return err
				}
				o := f.start(opts)
				id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.20")
				turn(t, o)
				want := admission.AuditID{Action: attemptOf(t, o, candidate(t, o, id)).Attempt.ID}
				crash(t, o, func() error {
					if err := o.deliverAudit(); err != nil {
						return err
					}
					if after == "the acknowledgement" {
						panic(killPoint{})
					}
					return nil
				})
				before := consumer.seen()
				if len(before) != map[bool]int{true: 1}[after == "the consumers" || after == "the acknowledgement"] {
					t.Fatalf("before the kill the consumers saw %v", before)
				}

				writtenBefore := writes(sink)
				o = f.start(opts)
				for range 2 {
					if err := o.do(o.deliverAudit); err != nil {
						t.Fatal(err)
					}
				}
				seen := consumer.seen()[len(before):]
				wantWrites := writtenBefore + 1
				if after == "the acknowledgement" {
					wantWrites = writtenBefore
				}
				if writes(sink) != wantWrites {
					t.Fatalf("restart wrote %d audit batches; want %d", writes(sink), wantWrites)
				}
				if after == "the acknowledgement" {
					if len(seen) != 0 || writes(sink) != writtenBefore {
						t.Fatal("a restart redelivered an acknowledged row")
					}
					return
				}
				if len(seen) != 1 || len(seen[0]) != 1 || seen[0][0].State != admission.StateVerified || seen[0][0].Attempt.ID != want.Action {
					t.Fatalf("after the restart the consumers saw %v; want the applied row of %s once", seen, want.Action)
				}
				if len(before) == 1 && before[0][0].ID() != seen[0][0].ID() {
					t.Fatalf("the row came again as %v; first seen as %v", seen[0][0].ID(), before[0][0].ID())
				}
				written := writes(sink)
				if err := o.do(o.deliverAudit); err != nil {
					t.Fatal(err)
				}
				if writes(sink) != written || len(consumer.seen()) != len(before)+1 {
					t.Fatal("rows came again after their acknowledgement")
				}
			})
		})
	}
}

// writes counts the action log writes s took.
func writes(s *auditSink) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.batches)
}

// sameNames reports whether a and b hold the same names, in any order.
func sameNames(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}
