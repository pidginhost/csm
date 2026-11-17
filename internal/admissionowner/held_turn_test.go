package admissionowner

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// heldTurns is an odd count, so a turn that still selected while held
// leaves the two-scope rotation on the scope served before the hold.
const heldTurns = 9

func heldStateProbes(blocks *fakeBlocks) int {
	var n int
	blocks.set(func(b *fakeBlocks) { n = b.stateProbes })
	return n
}

// A turn while execution is held and its probe is not due runs no block
// pick, so it must not spend fair turns: new work is still labelled as
// waiting for the engine, and the first batch after the hold serves the
// scope whose turn came next. Every hold kind and both entry points.
func TestOwnerHeldTurnsKeepTheRotation(t *testing.T) {
	for _, ticker := range []bool{false, true} {
		for _, kind := range []string{"state", "apply", "probe", "nil_engine", "rules", "confirm"} {
			name := "turn/" + kind
			if ticker {
				name = "schedule/" + kind
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
				served := func() map[string]int {
					n := map[string]int{}
					for id, scope := range scopes {
						if c := candidate(t, o, id); c.State == admission.StateVerified {
							n[scope]++
						}
					}
					return n
				}
				run()
				first := served()
				if first["alice"]+first[""] != 1 || selections != 1 {
					t.Fatalf("first batch served %v, selections %d", first, selections)
				}
				step := func(d time.Duration) {
					mono.advance(d)
					f.host.advance(d)
				}
				step(batchEvery)
				// The hold of a fault met again on later probes: the next
				// probe is half a minute away.
				if err := o.do(func() error {
					switch kind {
					case "state":
						o.hold(firewall.ErrBlockBatchState, false)
					case "apply":
						cause := errors.New("apply unavailable")
						blocks.set(func(b *fakeBlocks) { b.applyErr = cause })
						o.hold(cause, true)
					case "probe":
						cause := errors.New("check unavailable")
						blocks.set(func(b *fakeBlocks) { b.checkErr = cause })
						o.hold(cause, false)
						o.probeCheck = true
					case "nil_engine":
						running = false
						o.hold(errNoEngine, false)
					case "rules", "confirm":
						cause := firewall.ErrBlockRules
						if kind == "confirm" {
							cause = firewall.ErrConfirmPending
						}
						blocks.set(func(b *fakeBlocks) { b.checkErr = cause })
						o.hold(cause, false)
					}
					o.probeWait, o.probeAt = 30*time.Second, monoNow().Add(30*time.Second)
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				for range heldTurns {
					run()
					step(time.Second)
				}
				if selections != 1 {
					t.Errorf("held turns selected %d times, want none", selections-1)
				}
				for id := range scopes {
					c := candidate(t, o, id)
					if c.State == admission.StateQueued && (c.Attempts != 0 || c.Reason != admission.ReasonEngineUnavailable) {
						t.Errorf("held work lost its deferral: reason %v, attempts %d", c.Reason, c.Attempts)
					}
				}
				checks, applies := blocks.calls()
				if len(checks) != 1 || len(applies) != 1 || blocks.probes() != 0 || heldStateProbes(blocks) != 0 {
					t.Fatalf("held engine calls: checks=%d applies=%d probes=%d", len(checks), len(applies), blocks.probes())
				}
				if err := o.do(func() error {
					running = true
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				blocks.set(func(b *fakeBlocks) { b.applyErr, b.checkErr = nil, nil })
				if kind != "nil_engine" {
					step(30*time.Second - heldTurns*time.Second)
				}
				run()
				if n := served(); n["alice"] != 1 || n[""] != 1 {
					t.Fatalf("first batch after the hold served %v, want the other scope", n)
				}
				if err := o.do(func() error {
					if o.execHold != nil {
						t.Errorf("hold kept after a good probe and batch: %v", o.execHold)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// A new Critical arrival during a long hold is labelled and announced
// once, even though no selection or batch can run yet.
func TestOwnerHeldArrivalKeepsItsNotice(t *testing.T) {
	for _, ticker := range []bool{false, true} {
		name := "turn"
		if ticker {
			name = "schedule"
		}
		t.Run(name, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			sink := &noticeSink{}
			opts := executeOptions(f, blocks)
			opts.Deliver = sink.deliver
			o := f.start(opts)
			mono := heldMono(t, o)
			if err := o.do(func() error {
				o.hold(firewall.ErrBlockBatchState, false)
				o.probeWait, o.probeAt = maxProbeWait, mono.read().Add(maxProbeWait)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.30")
			selections := 0
			setOwnerHook(t, o, &scheduleLedger, func(l *store.AdmissionLedger, lim admission.ScheduleLimits, answers map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
				selections++
				return l.Schedule(lim, answers)
			})
			var transitions uint32
			for i := range 3 {
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
				c := candidate(t, o, id)
				if c.State != admission.StateQueued || c.Reason != admission.ReasonEngineUnavailable || c.Attempts != 0 {
					t.Fatalf("held arrival lost its label: %+v", c)
				}
				if i == 0 {
					transitions = c.Transitions
				} else if c.Transitions != transitions {
					t.Fatalf("held arrival was labelled again: %d, want %d", c.Transitions, transitions)
				}
				mono.advance(time.Second)
				f.host.advance(time.Second)
			}
			if selections != 0 {
				t.Errorf("held arrival spent %d selections", selections)
			}
			checks, applies := blocks.calls()
			if len(checks) != 0 || len(applies) != 0 || blocks.probes() != 0 || heldStateProbes(blocks) != 0 {
				t.Fatal("held arrival reached execution before the probe")
			}
			o.notices.cycle()
			if sink.count() != 1 || sink.lastPreview() {
				t.Fatalf("held arrival notice deliveries=%d, want one live delivery", sink.count())
			}
			keyed := 0
			for _, fd := range sink.last() {
				if strings.Contains(fd.Details, "reason=engine_unavailable") {
					keyed++
					if fd.Severity != alert.Critical || !strings.Contains(fd.Details, string(id)) || !strings.HasPrefix(fd.Details, "events=1 ") {
						t.Errorf("held arrival notice = %+v", fd)
					}
				}
			}
			if keyed != 1 {
				t.Fatalf("held arrival keyed notices=%d, want one", keyed)
			}
			o.notices.cycle()
			if sink.count() != 1 {
				t.Fatal("held arrival notice repeated")
			}
		})
	}
}

// Skipped turns cannot move terminal refusals past the next due probe.
// An apply hold still checks every member and applies only one survivor.
func TestOwnerHeldProbeEndsRefusals(t *testing.T) {
	for _, ticker := range []bool{false, true} {
		name := "turn"
		if ticker {
			name = "schedule"
		}
		t.Run(name, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			refused := []struct {
				ip      string
				refusal firewall.BlockRefusal
				reason  admission.Reason
			}{
				{"192.0.2.40", firewall.BlockRefusedExpired, admission.ReasonStale},
				{"192.0.2.41", firewall.BlockRefusedProtected, admission.ReasonProtected},
				{"192.0.2.42", firewall.BlockRefusedInvalid, admission.ReasonInvalid},
			}
			ids := make([]admission.CandidateID, len(refused))
			for i, r := range refused {
				ids[i], _ = queuedAt(t, o, p, f.host, admission.SeverityHigh, r.ip)
				blocks.set(func(b *fakeBlocks) { b.refuse[r.ip] = r.refusal })
			}
			good, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.43")
			if err := o.do(func() error {
				o.hold(errors.New("apply unavailable"), true)
				o.probeWait, o.probeAt = 30*time.Second, mono.read().Add(30*time.Second)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			run := func() {
				t.Helper()
				if err := o.do(func() error {
					if ticker {
						o.schedule()
						return o.scheduleErr
					}
					return o.turn()
				}); err != nil {
					t.Fatal(err)
				}
			}
			run()
			mono.advance(30*time.Second - time.Nanosecond)
			f.host.advance(30*time.Second - time.Nanosecond)
			run()
			if blocks.probes() != 0 || heldStateProbes(blocks) != 0 {
				t.Fatal("refusal probe ran early")
			}
			mono.advance(time.Nanosecond)
			f.host.advance(time.Nanosecond)
			run()
			for i, r := range refused {
				want := admission.StateRefused
				if r.reason == admission.ReasonStale {
					want = admission.StateDropped
				}
				if c := candidate(t, o, ids[i]); c.State != want || c.Reason != r.reason || c.Attempts != 0 {
					t.Errorf("due probe delayed refusal %v: %+v", r.reason, c)
				}
			}
			if c := candidate(t, o, good); c.State != admission.StateVerified || c.Attempts != 1 {
				t.Fatalf("due probe did not resume execution: %+v", c)
			}
			checks, applies := blocks.calls()
			if heldStateProbes(blocks) != 1 || len(checks) != 1 || len(checks[0]) != 4 || len(applies) != 1 || len(applies[0]) != 1 || executionHeld(t, o) != "" {
				t.Fatalf("due probe: probes=%d checks=%v applies=%v held=%q", heldStateProbes(blocks), checks, applies, executionHeld(t, o))
			}
		})
	}
}
