package admissionowner

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/verdict"
)

// parity is an executable owner set up as a legacy gate test sets up the
// engine: a live or dry-run policy and, unless answer is nil, a panel
// callback that answers with answer. It records the reason of every call.
type parity struct {
	p       *admission.Producer
	f       *ownerFixture
	opts    Options
	o       *Owner
	mono    *fakeMono
	blocks  *fakeBlocks
	panel   *fakePanel
	w       *exampleWrites
	mu      sync.Mutex
	reasons []string
}

func newParity(t *testing.T, dry bool, answer func(string) (verdict.Response, error)) *parity {
	t.Helper()
	pt := &parity{p: withTestRegistry(t), f: newOwnerFixture(t), blocks: newFakeBlocks(), panel: newFakePanel("")}
	policy := validPolicy(1)
	policy.DryRun = dry
	if answer != nil {
		pt.panel.answer = answer
		policy.VerdictEnabled = true
		policy.AskVerdict = func(ctx context.Context, ip, reason string) (verdict.Response, error) {
			pt.mu.Lock()
			pt.reasons = append(pt.reasons, reason)
			pt.mu.Unlock()
			return pt.panel.ask(ctx, ip, reason)
		}
	}
	pt.opts = executeOptions(pt.f, pt.blocks)
	pt.opts.Policy = (&policyReader{p: policy}).read
	pt.start(t)
	return pt
}

// start starts the owner, or a new one after a stop.
func (pt *parity) start(t *testing.T) {
	t.Helper()
	pt.o = pt.f.start(pt.opts)
	pt.mono = heldMono(t, pt.o)
	pt.w = watchExamples(t, pt.o)
}

// decide runs the turns a decision needs: one asks the panel, the next
// uses its answer once every call has returned.
func (pt *parity) decide(t *testing.T) {
	t.Helper()
	turn(t, pt.o)
	eventually(t, "the panel", func() bool { return verdictState(t, pt.o).Pending == 0 })
	pt.mono.advance(batchEvery)
	turn(t, pt.o)
}

// block queues a block of addr.
func (pt *parity) block(t *testing.T, addr string) admission.CandidateID {
	t.Helper()
	id, _ := queuedAt(t, pt.o, pt.p, pt.f.host, admission.SeverityHigh, addr)
	return id
}

// outcome is how id's pick ended and what the decision touched: its state
// and reason, a dry-run ending's prediction, the calls asked, the batches
// applied and the examples written.
func (pt *parity) outcome(t *testing.T, id admission.CandidateID) string {
	t.Helper()
	c := candidate(t, pt.o, id)
	s := c.State.String()
	if c.Reason != 0 {
		s += " " + c.Reason.String()
	}
	if fc := forecastOf(t, pt.o); fc != nil {
		for p, n := range fc.picks {
			if n != 0 {
				s += fmt.Sprintf(" %s=%d", admission.Prediction(p), n)
			}
		}
	}
	asked, _, _, _ := pt.panel.state()
	_, applies := pt.blocks.calls()
	examples := 0
	for _, batch := range pt.w.written() {
		examples += len(batch)
	}
	return fmt.Sprintf("%s asked=%d applies=%d examples=%d", s, len(asked), len(applies), examples)
}

func answerWith(v string) func(string) (verdict.Response, error) {
	return func(string) (verdict.Response, error) { return verdict.Response{Verdict: v}, nil }
}

func answerError(string) (verdict.Response, error) {
	return unconfiguredClient.Ask(context.Background(), verdict.Request{})
}

// Spec 4.5, 6.5: the legacy gate tests in internal/firewall and
// internal/checks pin how the panel callback and dry run meet the local
// checks. Each case is named after its legacy fixture and runs the same
// decision through the owner under a live and a dry-run policy. The owner
// keeps the legacy order: local refusals and real effects before the
// callback, an allow before dry run, block, empty or error continuing the
// local path. A dry run records its forecast where legacy recorded a
// would-have-blocked line.
func TestOwnerKeepsTheLegacyGates(t *testing.T) {
	for _, tc := range []struct {
		legacy    string
		answer    func(string) (verdict.Response, error)
		refusal   firewall.BlockRefusal
		addr      string
		live, dry string
	}{
		{
			legacy: "TestBlockIPOutcome_VerdictAllowReturnsAllowed", answer: answerWith("allow"), addr: "192.0.2.6",
			live: "refused verdict_allow asked=1 applies=0 examples=0",
			dry:  "refused verdict_allow asked=1 applies=0 examples=0",
		},
		{
			legacy: "TestBlockIP_VerdictBlockProceedsToDefault", answer: answerWith("block"), addr: "192.0.2.1",
			live: "verified asked=1 applies=1 examples=0",
			dry:  "dry_run capacity_admit=1 asked=1 applies=0 examples=1",
		},
		{
			legacy: "TestBlockIP_VerdictErrorProceedsToDefault", answer: answerError, addr: "192.0.2.1",
			live: "verified asked=1 applies=1 examples=0",
			dry:  "dry_run capacity_admit=1 asked=1 applies=0 examples=1",
		},
		{
			legacy: "TestBlockIP_VerdictBlockProceedsToDefault/empty", answer: answerWith(""), addr: "192.0.2.1",
			live: "verified asked=1 applies=1 examples=0",
			dry:  "dry_run capacity_admit=1 asked=1 applies=0 examples=1",
		},
		{
			legacy: "TestBlockIP_VerdictNotCalledWhenLocalValidationFails", answer: answerWith("allow"), refusal: firewall.BlockRefusedProtected, addr: "192.0.2.10",
			live: "refused protected asked=0 applies=0 examples=0",
			dry:  "refused protected asked=0 applies=0 examples=0",
		},
		{
			legacy: "TestBlockIP_VerdictAllowDoesNotHideInvalidIP", answer: answerWith("allow"), refusal: firewall.BlockRefusedInvalid, addr: "192.0.2.10",
			live: "refused invalid asked=0 applies=0 examples=0",
			dry:  "refused invalid asked=0 applies=0 examples=0",
		},
		{
			legacy: "TestBlockIPOutcome_SkipsAllowedIP", answer: answerWith("block"), refusal: firewall.BlockRefusedAllowed, addr: "192.0.2.10",
			live: "refused protected asked=0 applies=0 examples=0",
			dry:  "refused protected asked=0 applies=0 examples=0",
		},
		{
			// Legacy answers no-op; the owner ends a live pick linked to the
			// block and a dry-run pick as existing_actual.
			legacy: "TestBlockIPAlreadyBlockedNoopsBeforeNftablesAndAudit", answer: answerWith("allow"), refusal: firewall.BlockRefusedExisting, addr: "192.0.2.44",
			live: "refused existing_effect asked=0 applies=0 examples=0",
			dry:  "dry_run existing_actual=1 asked=0 applies=0 examples=0",
		},
		{
			legacy: "TestBlockIPOutcome_DryRunReturnsDryRun", addr: "192.0.2.5",
			live: "verified asked=0 applies=1 examples=0",
			dry:  "dry_run capacity_admit=1 asked=0 applies=0 examples=1",
		},
		{
			legacy: "TestBlockIPOutcome_IPv6ReachesDryRunWhenSetExists", addr: "2001:db8::1",
			live: "verified asked=0 applies=1 examples=0",
			dry:  "dry_run capacity_admit=1 asked=0 applies=0 examples=1",
		},
		{
			legacy: "TestBlockIP_DryRunPreservesInfraSafetyCheck", refusal: firewall.BlockRefusedProtected, addr: "192.0.2.10",
			live: "refused protected asked=0 applies=0 examples=0",
			dry:  "refused protected asked=0 applies=0 examples=0",
		},
	} {
		for _, dry := range []bool{false, true} {
			mode, want := "live", tc.live
			if dry {
				mode, want = "dry_run", tc.dry
			}
			t.Run(tc.legacy+"/"+mode, func(t *testing.T) {
				pt := newParity(t, dry, tc.answer)
				if tc.refusal != "" {
					pt.blocks.refuse[tc.addr] = tc.refusal
				}
				id := pt.block(t, tc.addr)
				pt.decide(t)
				if got := pt.outcome(t, id); got != want {
					t.Fatalf("outcome = %q, want %q", got, want)
				}
				var attempts uint32
				if strings.HasPrefix(want, "verified ") {
					attempts = 1
				}
				c := candidate(t, pt.o, id)
				if used := liveUsed(t, pt.o); used != attempts || c.Attempts != attempts {
					t.Fatalf("%d live units, %d attempts; want %d of each", used, c.Attempts, attempts)
				}
				if rows := pendingAudit(t, pt.o); len(rows) != 3*int(attempts) {
					t.Fatalf("%d attempt audit rows, want %d", len(rows), 3*attempts)
				}
				if attempts != 0 {
					_, batches := pt.blocks.calls()
					a, err := admission.NewAttempt(id, 1)
					if err != nil {
						t.Fatal(err)
					}
					wantMember := firewall.BlockMember{Action: string(a.ID), IP: tc.addr, Reason: "CSM auto-block: ssh_brute", ExpiresAt: pt.f.host.now().Add(24 * time.Hour)}
					if len(batches) != 1 || len(batches[0]) != 1 || batches[0][0] != wantMember {
						t.Fatalf("applied %v, want exactly %v", batches, wantMember)
					}
				}
			})
		}
	}
}

// Spec 3.3, 4.1: legacy rechecks an allow added while the panel was asked
// (TestBlockIPOutcome_RechecksAllowAfterVerdict). The owner revalidates
// before it uses any answer, in both modes: the pick is refused as
// protected and the panel's allow ends nothing.
func TestOwnerRechecksProtectionAfterTheCallback(t *testing.T) {
	for _, dry := range []bool{false, true} {
		t.Run(fmt.Sprint("dry_run=", dry), func(t *testing.T) {
			pt := newParity(t, dry, answerWith("allow"))
			release := make(chan struct{})
			pt.panel.hold = release
			id := pt.block(t, "192.0.2.10")
			turn(t, pt.o)
			eventually(t, "the call", func() bool { _, active, _, _ := pt.panel.state(); return active == 1 })
			pt.blocks.set(func(b *fakeBlocks) { b.refuse["192.0.2.10"] = firewall.BlockRefusedAllowed })
			close(release)
			readyAnswers(t, pt.o, 1)
			turn(t, pt.o)
			if got, want := pt.outcome(t, id), "refused protected asked=1 applies=0 examples=0"; got != want {
				t.Fatalf("outcome = %q, want %q", got, want)
			}
			if s := verdictState(t, pt.o); s.AllowEndings != 0 {
				t.Fatalf("an allow ended a protected pick: %+v", s)
			}
		})
	}
}

// Spec 4.5: the changes the design makes to legacy on purpose, each named
// after the legacy fixture whose behaviour changes, with the owner's
// expected behaviour. Concurrent calls, aggregated examples and notices,
// fresh requests for a retry and discarding old answers on reload are
// pinned by TestOwnerBoundsVerdictCalls, TestOwnerSummarizesADryRunMinute,
// TestOwnerAsksAgainForARetry and TestOwnerRetiresVerdictsOnANewEpoch.
func TestOwnerChangesLegacyGatesOnPurpose(t *testing.T) {
	// Legacy fails open into the default block when shutdown cancels the
	// callback. The owner never reads a cancellation as an answer: the
	// pick stays queued for a later process to ask again.
	t.Run("TestBlockIP_VerdictAbortsOnShutdownContext", func(t *testing.T) {
		for _, dry := range []bool{false, true} {
			pt := newParity(t, dry, answerWith("block"))
			pt.panel.hold = make(chan struct{})
			id := pt.block(t, "192.0.2.77")
			turn(t, pt.o)
			eventually(t, "the call", func() bool { _, active, _, _ := pt.panel.state(); return active == 1 })
			pt.o.Stop()
			if s := pt.o.Status().Owner.Verdict; s.Asked != 1 || s.Cancelled != 1 || s.ResponsesDefault+s.ResponsesAllow+s.Failed != 0 {
				t.Fatalf("dry_run=%v: counters after stop = %+v", dry, s)
			}
			pt.start(t)
			if got, want := pt.outcome(t, id), "queued asked=1 applies=0 examples=0"; got != want {
				t.Fatalf("dry_run=%v: outcome = %q, want %q", dry, got, want)
			}
		}
	})
	// Legacy asks the panel at the temporary cap, since it may evict to make
	// room. The owner models no eviction: a full real set defers a live pick
	// and ends a dry-run pick as set_full, without a call or a removal.
	t.Run("TestBlockIPOutcome_AllowVerdictAtTempCapDoesNotEvict", func(t *testing.T) {
		for dry, want := range map[bool]string{false: "queued set_full asked=0 applies=0 examples=0", true: "dry_run set_full=1 asked=0 applies=0 examples=0"} {
			pt := newParity(t, dry, answerWith("allow"))
			pt.blocks.temp, pt.blocks.limit = 1, 1
			id := pt.block(t, "192.0.2.21")
			pt.decide(t)
			if got := pt.outcome(t, id); got != want {
				t.Fatalf("dry_run=%v: outcome = %q, want %q", dry, got, want)
			}
			if retires := pt.blocks.retireCalls(); len(retires) != 0 {
				t.Fatalf("dry_run=%v: a full set evicted %v", dry, retires)
			}
		}
	})
	// Legacy asks again for every repeat in dry run, since nothing was
	// blocked. A forecast block already covers the repeat: it ends as
	// existing_shadow without a call.
	t.Run("TestBlockIP_VerdictBlockProceedsToDefault/repeat", func(t *testing.T) {
		pt := newParity(t, true, answerWith("block"))
		observe(t, pt.o, pt.p, pt.f, "192.0.2.1", "offset=1")
		pt.decide(t)
		pt.f.host.advance(time.Second)
		repeat := observe(t, pt.o, pt.p, pt.f, "192.0.2.1", "offset=2")
		pt.decide(t)
		if got, want := pt.outcome(t, repeat), "dry_run capacity_admit=1 existing_shadow=1 asked=1 applies=0 examples=1"; got != want {
			t.Fatalf("outcome = %q, want %q", got, want)
		}
	})
	// Legacy hands the panel the caller's free-text reason. The owner sends
	// only the registered check, in both modes.
	t.Run("TestBlockIP_VerdictAllowShortCircuits/reason", func(t *testing.T) {
		for _, dry := range []bool{false, true} {
			pt := newParity(t, dry, answerWith("allow"))
			pt.block(t, "192.0.2.1")
			pt.decide(t)
			pt.mu.Lock()
			reasons := slices.Clone(pt.reasons)
			pt.mu.Unlock()
			if want := []string{"CSM auto-block: ssh_brute"}; !slices.Equal(reasons, want) {
				t.Fatalf("dry_run=%v: reasons = %q, want %q", dry, reasons, want)
			}
		}
	})
	// Legacy promotes a repeat offender to a permanent block whatever the
	// dry-run setting. A dry run suppresses the promotion: it ends as
	// not_modelled without a call or an engine read. Live, the owner only
	// previews it until promotions run (plan 1.6), and never asks.
	t.Run("TestAutoBlockIPs_PromotesRepeatOffenderToPermanentBlock", func(t *testing.T) {
		for dry, want := range map[bool]string{false: "observed asked=0 applies=0 examples=0", true: "dry_run not_modelled=1 asked=0 applies=0 examples=0"} {
			pt := newParity(t, dry, answerWith("allow"))
			id, _ := queuedKind(t, pt.o, pt.p, pt.f.host, admission.SeverityHigh, "192.0.2.20", admission.KindPromote)
			pt.decide(t)
			if got := pt.outcome(t, id); got != want {
				t.Fatalf("dry_run=%v: outcome = %q, want %q", dry, got, want)
			}
			pt.blocks.set(func(b *fakeBlocks) {
				if len(b.snapshots)+len(b.checks) != 0 {
					t.Errorf("dry_run=%v: a promotion read the engine", dry)
				}
			})
		}
	})
}

// Spec 4.5: subnets honour dry run without the callback, as legacy does
// (TestAutoBlockIPs_NetBlockDryRunSkipsBlockSubnet): the pick ends as a
// not_modelled dry run with no call. Re-proof, startup settlement and the
// retirement of an unknown attempt never ask either, and never execute
// anything new.
func TestOwnerAsksOnlyForNewBlockAttempts(t *testing.T) {
	t.Run("TestAutoBlockIPs_NetBlockDryRunSkipsBlockSubnet", func(t *testing.T) {
		pt := newParity(t, true, answerWith("allow"))
		prefix, err := admission.CanonicalPrefix("198.51.100.0/24", admission.Caps{IPv6: true})
		if err != nil {
			t.Fatal(err)
		}
		id, _ := queuedTarget(t, pt.o, pt.p, pt.f.host, admission.SeverityHigh, "198.51.100.7", admission.KindBlockSubnet, prefix)
		pt.decide(t)
		if got, want := pt.outcome(t, id), "dry_run not_modelled=1 asked=0 applies=0 examples=0"; got != want {
			t.Fatalf("outcome = %q, want %q", got, want)
		}
	})
	t.Run("recovery", func(t *testing.T) {
		pt := newParity(t, false, answerWith("block"))
		pt.blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockUnknown}
		id := pt.block(t, "192.0.2.10")
		pt.decide(t)
		c := candidate(t, pt.o, id)
		if c.State != admission.StateUnknown {
			t.Fatalf("fixture: pick = %+v", c)
		}
		if err := pt.o.do(pt.o.deliverAudit); err != nil {
			t.Fatal(err)
		}
		pt.mono.advance(25 * time.Hour)
		pt.f.host.advance(25 * time.Hour)
		turn(t, pt.o)
		if a := attemptOf(t, pt.o, c); !a.Retired || len(pt.blocks.retireCalls()) != 1 {
			t.Fatalf("unknown attempt = %+v", a)
		}
		pt.o.Stop()
		pt.start(t)
		turn(t, pt.o)
		if asked, _, _, _ := pt.panel.state(); len(asked) != 1 {
			t.Fatalf("recovery asked the panel: %v", asked)
		}
		if _, applies := pt.blocks.calls(); len(applies) != 1 {
			t.Fatalf("recovery executed again: %d applies", len(applies))
		}
	})
	// A batch member the kernel found already blocked is proven again
	// before its pick ends linked to that block; the proof is a local
	// check, never another call.
	t.Run("re-proof", func(t *testing.T) {
		pt := newParity(t, false, answerWith("block"))
		pt.blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedExisting}
		id := pt.block(t, "192.0.2.10")
		pt.decide(t)
		checks, applies := pt.blocks.calls()
		if c := candidate(t, pt.o, id); c.Link == (admission.EffectLink{}) || len(checks) != 2 || len(applies) != 1 {
			t.Fatalf("re-proven pick = %+v after %d checks and %d applies", c, len(checks), len(applies))
		}
		if asked, _, _, _ := pt.panel.state(); len(asked) != 1 {
			t.Fatalf("the re-proof asked the panel: %v", asked)
		}
	})
}
