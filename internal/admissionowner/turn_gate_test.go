package admissionowner

import (
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/verdict"
)

// queuedFor queues a block of addr whose root names account; an empty
// account leaves the root to the host.
func queuedFor(t testing.TB, o *Owner, p *admission.Producer, host *fakeHost, account, addr string) admission.CandidateID {
	t.Helper()
	var id admission.CandidateID
	now := host.now()
	if err := o.do(func() error {
		target, err := admission.CanonicalAddress(addr, admission.Caps{IPv6: true})
		if err != nil {
			return err
		}
		in := admission.EvidenceInput{
			Check: "ssh_brute", FindingID: "0123456789abcdef", Severity: admission.SeverityHigh,
			Observation: admission.ObservationRef{Stream: "log:sshd_log", Cursor: cursorFor(addr), Version: 1},
			ObservedAt:  now, Parser: admission.ParserRef{Name: "sshd", Version: 1}, Target: target,
		}
		if account != "" {
			in.Claims = []admission.Claim{{Kind: admission.ClaimAccount, Value: account}}
			in.Inventory = o.ledger.Inventory()
		}
		e, err := p.Mint(in)
		if err != nil {
			return err
		}
		if e.Owner().IsHost() != (account == "") {
			t.Errorf("root of %s for %q has owner %s", addr, account, e.Owner().Key())
		}
		if _, err = o.ledger.PublishEvidence(e); err != nil {
			return err
		}
		ep, err := admission.ParseEpisodeID("00000000000000000000000000000001")
		if err != nil {
			return err
		}
		c, _, err := o.ledger.Enqueue(admission.CandidateRequest{Kind: admission.KindBlockIP, Target: target, Episode: ep, Generation: 1, Primary: e.ID()})
		if err != nil {
			return err
		}
		id, err = c.ID()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// A turn inside the batch gate runs no block pick, so it must not spend
// the scheduler's fair turns either (spec 5.3, 5.5): the next batch
// serves the scope whose turn came next, not the one served before.
func TestOwnerTurnInsideTheBatchGateKeepsTheRotation(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	one := func(l *store.AdmissionLedger, lim admission.ScheduleLimits, answers map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
		lim.Members = 1
		return l.Schedule(lim, answers)
	}
	setOwnerHook(t, o, &scheduleLedger, one)
	scope := map[admission.CandidateID]string{}
	for _, q := range []struct{ account, addr string }{
		{"alice", "192.0.2.10"}, {"alice", "192.0.2.11"}, {"", "192.0.2.20"}, {"", "192.0.2.21"},
	} {
		scope[queuedFor(t, o, p, f.host, q.account, q.addr)] = q.account
	}
	served := func() map[string]int {
		n := map[string]int{}
		for id, account := range scope {
			if c := candidate(t, o, id); c.State == admission.StateVerified {
				n[account]++
			}
		}
		return n
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if n := served(); n["alice"]+n[""] != 1 {
		t.Fatalf("first turn served %v", n)
	}
	mono.advance(batchEvery / 2)
	f.host.advance(batchEvery / 2)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if n := served(); n["alice"]+n[""] != 1 {
		t.Fatalf("a turn inside the batch gate served %v", n)
	}
	mono.advance(batchEvery / 2)
	f.host.advance(batchEvery / 2)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if n := served(); n["alice"] != 1 || n[""] != 1 {
		t.Fatalf("after two batches: served %v, want one per scope", n)
	}
	if _, applies := blocks.calls(); len(applies) != 2 {
		t.Fatalf("applies = %d, want 2", len(applies))
	}
}

// Slow reservations separate the ticker's selection deadline from the
// batch deadline. Neither entry point may spend that intervening turn,
// including while an outage must still be visible to the operator.
func TestOwnerBatchGatePreservesTurnsAndDeferrals(t *testing.T) {
	for _, ticker := range []bool{false, true} {
		for _, fault := range []string{"ready", "clock", "state", "apply", "probe", "nil_engine"} {
			name := "turn/" + fault
			if ticker {
				name = "schedule/" + fault
			}
			t.Run(name, func(t *testing.T) {
				p := withTestRegistry(t)
				f := newOwnerFixture(t)
				blocks := newFakeBlocks()
				opts := executeOptions(f, blocks)
				running := true
				opts.Blocks = func() BlockEngine {
					if running {
						return blocks
					}
					return nil
				}
				o := f.start(opts)
				mono := heldMono(t, o)
				selections := 0
				setOwnerHook(t, o, &scheduleLedger, func(l *store.AdmissionLedger, lim admission.ScheduleLimits, answers map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
					selections++
					lim.Members = 1
					return l.Schedule(lim, answers)
				})
				reserve := reserveLedger
				setOwnerHook(t, o, &reserveLedger, func(l *store.AdmissionLedger, id admission.CandidateID, lane admission.Lane, expires time.Time) (admission.Candidate, admission.AttemptRecord, bool, error) {
					mono.advance(100 * time.Millisecond)
					f.host.advance(100 * time.Millisecond)
					return reserve(l, id, lane, expires)
				})
				scopes := map[admission.CandidateID]string{}
				for _, q := range []struct{ account, addr string }{
					{"alice", "192.0.2.10"}, {"alice", "192.0.2.11"}, {"", "192.0.2.20"}, {"", "192.0.2.21"},
				} {
					scopes[queuedFor(t, o, p, f.host, q.account, q.addr)] = q.account
				}
				run := func() {
					t.Helper()
					if err := o.do(func() error {
						if ticker {
							o.scheduleDue = true
							o.schedule()
							return o.scheduleErr
						}
						return o.turn()
					}); err != nil {
						t.Fatal(err)
					}
				}
				run()
				before := map[admission.CandidateID]admission.Candidate{}
				verified := 0
				for id := range scopes {
					before[id] = candidate(t, o, id)
					if before[id].State == admission.StateVerified {
						verified++
					}
				}
				if verified != 1 || selections != 1 {
					t.Fatalf("first batch verified %d, selections %d", verified, selections)
				}
				charged := ceiling(t, o)
				var nextTurn, nextBatch time.Time
				if err := o.do(func() error {
					nextTurn, nextBatch = o.nextTurn, o.nextBatch
					switch fault {
					case "state":
						o.hold(firewall.ErrBlockBatchState, false)
					case "apply":
						o.hold(errors.New("apply unavailable"), true)
					case "probe":
						o.hold(errors.New("check unavailable"), false)
						o.probeCheck = true
					case "nil_engine":
						running = false
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				mono.advance(900 * time.Millisecond)
				f.host.advance(900 * time.Millisecond)
				if fault == "clock" {
					f.host.set(func(h *fakeHost) { h.wall = h.wall.Add(-time.Minute) })
				}
				run()
				for id, old := range before {
					c := candidate(t, o, id)
					if old.State == admission.StateQueued && fault != "ready" {
						if c.State != admission.StateQueued || c.Attempts != 0 || c.Reason != admission.ReasonEngineUnavailable {
							t.Errorf("gated outage lost its deferral: %+v", c)
						}
					} else if !reflect.DeepEqual(c, old) {
						t.Errorf("gated turn changed candidate: %+v, before %+v", c, old)
					}
				}
				if err := o.do(func() error {
					if selections != 1 || o.nextTurn != nextTurn || o.nextBatch != nextBatch || !o.scheduleDue {
						t.Errorf("gated turn spent selection: calls=%d next=%v/%v due=%t", selections, o.nextTurn, o.nextBatch, o.scheduleDue)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if got := ceiling(t, o); got.General.Used != charged.General.Used || got.Reserved.Used != charged.Reserved.Used {
					t.Fatalf("gated turn charged work: %+v, before %+v", got, charged)
				}
				checks, applies := blocks.calls()
				if len(checks) != 1 || len(applies) != 1 || blocks.probes() != 0 {
					t.Fatalf("gated engine calls: checks=%d applies=%d probes=%d", len(checks), len(applies), blocks.probes())
				}
				if fault == "clock" {
					f.host.advance(time.Minute)
				}
				if err := o.do(func() error { running = true; return nil }); err != nil {
					t.Fatal(err)
				}
				mono.advance(100 * time.Millisecond)
				f.host.advance(100 * time.Millisecond)
				run()
				served := map[string]int{}
				for id, scope := range scopes {
					if c := candidate(t, o, id); c.State == admission.StateVerified {
						served[scope]++
					}
				}
				if served["alice"] != 1 || served[""] != 1 {
					t.Fatalf("first turn after gate served %v, want one per scope", served)
				}
				if got := ceiling(t, o); got.General.Used != charged.General.Used+1 || got.Reserved.Used != charged.Reserved.Used {
					t.Fatalf("resumed batch charges %+v, before %+v", got, charged)
				}
			})
		}
	}
}

// A stale live batch deadline must not suppress a dry-run forecast or an
// observe preview without an engine. Their terminal state, not a request
// to forecast, proves the turn ran.
func TestOwnerBatchGateLeavesForecastsAndPreviews(t *testing.T) {
	for _, forecast := range []bool{false, true} {
		t.Run(map[bool]string{false: "preview", true: "forecast"}[forecast], func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			opts := previewOptions(f)
			if forecast {
				blocks := newFakeBlocks()
				opts = executeOptions(f, blocks)
				opts.Policy = func() ExecutionPolicy { return dryPolicy(1) }
			}
			o := f.start(opts)
			mono := heldMono(t, o)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			used := ceiling(t, o).General.Used
			if err := o.do(func() error {
				o.nextBatch = mono.read().Add(time.Hour)
				o.scheduleDue = true
				o.schedule()
				return o.scheduleErr
			}); err != nil {
				t.Fatal(err)
			}
			want, charge := admission.StateObserved, uint32(1)
			if forecast {
				want, charge = admission.StateDryRun, 0
			}
			if c := candidate(t, o, id); c.State != want || ceiling(t, o).General.Used != used+charge {
				t.Fatalf("preview/forecast suppressed by live gate: %+v", c)
			}
		})
	}
}

// A gated turn asks no new verdict and spends no selection. Once the gate
// opens the callback answer is consumed by a verified charged effect.
func TestOwnerBatchGateKeepsVerdictWork(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("block")
	o, _, mono := verdictOwner(t, f, blocks, panel)
	var selected []admission.Pick
	setOwnerHook(t, o, &scheduleLedger, func(l *store.AdmissionLedger, lim admission.ScheduleLimits, answers map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
		picks, err := l.Schedule(lim, answers)
		selected = append(selected, picks...)
		return picks, err
	})
	first, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	readyAnswers(t, o, 1)
	turn(t, o)
	if c := candidate(t, o, first); c.State != admission.StateVerified {
		t.Fatalf("first verdict effect: %+v", c)
	}
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	before, charged := candidate(t, o, id), ceiling(t, o)
	selectedBefore := append([]admission.Pick(nil), selected...)
	turn(t, o)
	if c := candidate(t, o, id); !reflect.DeepEqual(c, before) || ceiling(t, o) != charged || !reflect.DeepEqual(selected, selectedBefore) {
		t.Fatalf("gated verdict changed work: %+v", c)
	}
	if s := verdictState(t, o); s.Pending != 0 || s.Ready != 0 {
		t.Fatalf("gated verdict stage: %+v", s)
	}
	mono.advance(batchEvery)
	f.host.advance(batchEvery)
	turn(t, o)
	readyAnswers(t, o, 1)
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateVerified || c.Attempts != 1 || ceiling(t, o).General.Used != charged.General.Used+1 {
		t.Fatalf("resumed verdict did not verify one charged effect: %+v", c)
	}
}

// An outage inside the gate must not relabel a pending or allowed verdict
// as an engine deferral. Both answers still reach their own ending later.
func TestOwnerBatchGatePreservesPendingAndAllowedVerdicts(t *testing.T) {
	for _, answer := range []string{"block", "allow"} {
		t.Run(answer, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			panel := newFakePanel("block")
			reply := make(chan struct{})
			panel.answer = func(ip string) (verdict.Response, error) {
				if ip == "192.0.2.11" {
					<-reply
					return verdict.Response{Verdict: answer}, nil
				}
				return verdict.Response{Verdict: "block"}, nil
			}
			o, _, mono := verdictOwner(t, f, blocks, panel)
			released := false
			release := func() {
				if !released {
					close(reply)
					released = true
				}
			}
			t.Cleanup(release)
			first, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
			turn(t, o)
			readyAnswers(t, o, 1)
			turn(t, o)
			if c := candidate(t, o, first); c.State != admission.StateVerified {
				t.Fatalf("first effect not verified: %+v", c)
			}
			if answer == "allow" {
				release()
				readyAnswers(t, o, 1)
			}
			before, charged := candidate(t, o, id), ceiling(t, o)
			if err := o.do(func() error { o.hold(firewall.ErrBlockBatchState, false); return nil }); err != nil {
				t.Fatal(err)
			}
			turn(t, o)
			if c := candidate(t, o, id); !reflect.DeepEqual(c, before) || ceiling(t, o) != charged {
				t.Fatalf("gated outage relabeled verdict work: %+v", c)
			}
			release()
			readyAnswers(t, o, 1)
			mono.advance(batchEvery)
			f.host.advance(batchEvery)
			turn(t, o)
			want, charge := admission.StateVerified, uint32(1)
			if answer == "allow" {
				want, charge = admission.StateRefused, 0
			}
			if c := candidate(t, o, id); c.State != want || ceiling(t, o).General.Used != charged.General.Used+charge || (answer == "allow" && c.Reason != admission.ReasonVerdictAllow) {
				t.Fatalf("resumed verdict ending: %+v", c)
			}
		})
	}
}

// The turn deadline runs from the turn's start: a slow durable clock write
// must not push the next selection past the schedule ticker, which fires
// every turnEvery, or every selecting turn would wait two ticks.
func TestOwnerTurnDeadlineExcludesTheTick(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	opts := executeOptions(f, blocks)
	var slow atomic.Pointer[fakeMono]
	opts.Clock = func() (admission.ClockReading, error) {
		if m := slow.Load(); m != nil {
			m.advance(5 * time.Millisecond)
		}
		return f.host.clock()
	}
	o := f.start(opts)
	mono := heldMono(t, o)
	slow.Store(mono)
	selections := 0
	setOwnerHook(t, o, &scheduleLedger, func(l *store.AdmissionLedger, lim admission.ScheduleLimits, answers map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
		selections++
		return l.Schedule(lim, answers)
	})
	ticker := func() {
		t.Helper()
		if err := o.do(func() error {
			o.scheduleDue = true
			o.schedule()
			return o.scheduleErr
		}); err != nil {
			t.Fatal(err)
		}
	}
	start := mono.read()
	ticker()
	mono.advance(start.Add(turnEvery).Sub(mono.read()))
	ticker()
	if selections != 2 {
		t.Fatalf("a turn one period after the last one's start selected %d times in all, want 2", selections)
	}
}

// An outage inside the batch gate defers waiting work that nothing else
// holds back, but leaves a capacity deferral as it is: relabelling it would
// cost a write per candidate and the next served turn would write it back.
func TestOwnerBatchGateKeepsCapacityDeferrals(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	first, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	if c := candidate(t, o, first); c.State != admission.StateVerified {
		t.Fatalf("first block = %+v", c)
	}
	full, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	fresh, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	if err := o.do(func() error {
		_, err := o.ledger.Defer(full, admission.ReasonSetFull)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	before := candidate(t, o, full)
	if err := o.do(func() error { o.hold(errors.New("apply unavailable"), true); return nil }); err != nil {
		t.Fatal(err)
	}
	mono.advance(batchEvery / 2)
	turn(t, o)
	if c := candidate(t, o, full); c.Reason != admission.ReasonSetFull || c.Transitions != before.Transitions {
		t.Fatalf("a capacity deferral was relabelled: %+v, before %+v", c, before)
	}
	if c := candidate(t, o, fresh); c.State != admission.StateQueued || c.Reason != admission.ReasonEngineUnavailable {
		t.Fatalf("waiting work lost its outage deferral: %+v", c)
	}
}
