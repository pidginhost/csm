package admissionowner

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// A capacity-blocked head in the same scope must not hide a disabled
// lower-priority response from policy revalidation.
func TestOwnerDisabledWorkBehindBlockedHead(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	policy := validPolicy(1)
	policy.CeilingLimit = 2
	policy.Allows = func(c admission.Candidate) bool {
		addr, _ := c.Key.Target.Addr()
		return addr.String() != "192.0.2.10"
	}
	o, _, mono := policyOwner(t, f, blocks, policy)
	queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	turn(t, o)
	mono.advance(batchEvery)
	on, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.12")
	off, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	if c := candidate(t, o, off); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 {
		t.Fatalf("disabled work behind a blocked head = %s/%s, attempts %d", c.State, c.Reason, c.Attempts)
	}
	if c := candidate(t, o, on); c.State != admission.StateQueued || c.Reason != admission.ReasonCeiling || c.Attempts != 0 {
		t.Fatalf("allowed work bypassed capacity: %+v", c)
	}
}

// Retry pacing delays another execution, not refusal after an opt-out.
func TestOwnerDisabledRetryDoesNotWaitForBackoff(t *testing.T) {
	for _, dry := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "forecast"}[dry], func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			first := validPolicy(1)
			first.DryRun = dry
			o, reader, _ := policyOwner(t, f, blocks, first)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			if err := o.do(func() error {
				_, a, _, err := o.ledger.Reserve(id, admission.LaneGeneral, o.now.Add(time.Hour))
				if err != nil {
					return err
				}
				_, _, err = o.ledger.Finish(a.Attempt.ID, admission.DispositionFailed)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			before := candidate(t, o, id)
			if before.State != admission.StateQueued || !before.NotBefore.After(f.host.now()) {
				t.Fatalf("fixture is not a waiting retry: %+v", before)
			}
			charged := ceiling(t, o)
			next := first
			next.Epoch++
			next.Allows = func(admission.Candidate) bool { return false }
			reader.publish(next)
			turn(t, o)
			if c := candidate(t, o, id); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != before.Attempts || !c.ExpiresAt.Equal(before.ExpiresAt) {
				t.Fatalf("disabled retry = %+v", c)
			}
			checks, applies := blocks.calls()
			if ceiling(t, o) != charged || len(checks) != 0 || len(applies) != 0 || len(blocks.snapshots) != 0 || f.db.DryRunBlocksCount() != 0 {
				t.Fatal("disabled retry changed capacity or reached the engine")
			}
		})
	}
}

// Refusing disabled work must not require or consume the scheduler's live
// budget, including when another response spends its final unit.
func TestOwnerDisabledWorkNeedsNoSchedulingCredit(t *testing.T) {
	for _, live := range []bool{false, true} {
		for _, spent := range []bool{false, true} {
			t.Run(map[bool]string{false: "preview", true: "live"}[live]+"/"+map[bool]string{false: "last_unit", true: "spent"}[spent], func(t *testing.T) {
				withLiveExecution(t, live)
				p := withTestRegistry(t)
				f := newOwnerFixture(t)
				blocks := newFakeBlocks()
				policy := validPolicy(1)
				policy.CeilingLimit = 2
				policy.Allows = func(c admission.Candidate) bool {
					addr, _ := c.Key.Target.Addr()
					return addr.String() != "192.0.2.10"
				}
				o, _, mono := policyOwner(t, f, blocks, policy)
				on, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
				if spent {
					turn(t, o)
					if ceiling(t, o).Budget(admission.LaneGeneral) != 0 {
						t.Fatal("fixture still has general credit")
					}
					mono.advance(batchEvery)
				}
				off, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.10")
				turn(t, o)
				if c := candidate(t, o, off); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 {
					t.Errorf("disabled work = %s/%s, attempts %d", c.State, c.Reason, c.Attempts)
				}
				want := admission.StateObserved
				if live {
					want = admission.StateVerified
				}
				if c := candidate(t, o, on); c.State != want || c.Attempts != 1 {
					t.Errorf("allowed work = %s/%s, attempts %d; want %s/1", c.State, c.Reason, c.Attempts, want)
				}
				if used := liveUsed(t, o); used != 1 {
					t.Errorf("ceiling charged %d units, want 1", used)
				}
			})
		}
	}
}

// Admission-gates section 8, row 1: queued work whose response the
// configuration no longer allows ends refused as disabled at its next
// turn, live or dry run, before any panel ask, engine check, forecast or
// reservation. Allowed work beside it runs as before.
func TestOwnerRefusesWorkTheConfigurationTurnedOff(t *testing.T) {
	for _, tc := range []struct {
		name      string
		live, dry bool
	}{
		{"live", true, false},
		{"dry_run", true, true},
		{"production_preview", false, false},
		{"production_forecast", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withLiveExecution(t, tc.live)
			dry := tc.dry
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			panel := newFakePanel("")
			policy := verdictPolicy(1, panel)
			policy.DryRun = dry
			policy.Allows = func(c admission.Candidate) bool {
				addr, _ := c.Key.Target.Addr()
				return addr.String() != "192.0.2.10"
			}
			opts := executeOptions(f, blocks)
			opts.Policy = (&policyReader{p: policy}).read
			o := f.start(opts)
			mono := heldMono(t, o)
			off, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.10")
			on, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
			turn(t, o)
			eventually(t, "the panel", func() bool { return verdictState(t, o).Pending == 0 })
			mono.advance(batchEvery)
			turn(t, o)
			if c := candidate(t, o, off); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 {
				t.Fatalf("turned-off pick = %+v", c)
			}
			asked, _, _, _ := panel.state()
			if !tc.live && !dry {
				if len(asked) != 0 {
					t.Fatalf("preview asked the panel: %v", asked)
				}
			} else if len(asked) != 1 || asked[0] != "192.0.2.11" {
				t.Fatalf("the panel was asked about %v", asked)
			}
			checks, applies := blocks.calls()
			for _, batch := range append(append(checks, applies...), blocks.snapshots...) {
				for _, m := range batch {
					if m.IP == "192.0.2.10" {
						t.Fatalf("the engine saw a turned-off pick: %+v", m)
					}
				}
			}
			want := admission.StateVerified
			if dry {
				want = admission.StateDryRun
			} else if !tc.live {
				want = admission.StateObserved
			}
			if c := candidate(t, o, on); c.State != want {
				t.Fatalf("allowed pick = %+v, want %s", c, want)
			}
			var notices []admission.NoticeRecord
			if err := o.do(func() (err error) { notices, err = o.ledger.PendingNotices(); return err }); err != nil {
				t.Fatal(err)
			}
			for _, n := range notices {
				if n.Key.Kind == admission.NoticeWithheld {
					t.Fatalf("a turned-off Critical pick raised %+v", n)
				}
			}
		})
	}
}

// Disabling while an answer waits must win over that old answer in both
// modes. Neither a new ask nor an engine check is allowed for the pick.
func TestOwnerDisableRetiresPendingVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dry, ready bool
	}{
		{"live_pending", false, false},
		{"live_ready", false, true},
		{"dry_pending", true, false},
		{"dry_ready", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dry := tc.dry
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			panel := newFakePanel("allow")
			if !tc.ready {
				panel.hold = make(chan struct{})
			}
			first := verdictPolicy(1, panel)
			first.DryRun = dry
			o, r, mono := policyOwner(t, f, blocks, first)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.10")
			turn(t, o)
			if tc.ready {
				readyAnswers(t, o, 1)
			} else {
				eventually(t, "pending callback", func() bool { _, active, _, _ := panel.state(); return active == 1 })
			}
			checks, applies := blocks.calls()
			snapshots := len(blocks.snapshots)
			next := verdictPolicy(2, panel)
			next.DryRun = dry
			next.Allows = func(admission.Candidate) bool { return false }
			r.publish(next)
			if err := o.Reload(); err != nil {
				t.Fatal(err)
			}
			if !tc.ready {
				eventually(t, "cancelled callback", func() bool { _, active, _, cancelled := panel.state(); return active == 0 && cancelled == 1 })
			}
			mono.advance(batchEvery)
			turn(t, o)
			if c := candidate(t, o, id); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 {
				t.Fatalf("disabled pending pick = %+v", c)
			}
			afterChecks, afterApplies := blocks.calls()
			if asked, _, _, _ := panel.state(); len(asked) != 1 || len(afterChecks) != len(checks) || len(afterApplies) != len(applies) || len(blocks.snapshots) != snapshots || f.db.DryRunBlocksCount() != 0 || liveUsed(t, o) != 0 {
				t.Fatalf("disabled pending work reached a side effect: asks=%v checks=%d applies=%d snapshots=%d", asked, len(afterChecks), len(afterApplies), len(blocks.snapshots))
			}
		})
	}
}

// Restart revalidates persisted work against the new configuration even
// when the new process reuses the old policy epoch number.
func TestOwnerDisableAfterRestartUsesNewPolicy(t *testing.T) {
	for _, dry := range []bool{false, true} {
		t.Run(map[bool]string{false: "preview", true: "forecast"}[dry], func(t *testing.T) {
			withLiveExecution(t, false)
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			first := validPolicy(1)
			first.DryRun = dry
			o, _, _ := policyOwner(t, f, newFakeBlocks(), first)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.10")
			if c := candidate(t, o, id); c.State != admission.StateQueued || c.Attempts != 0 {
				t.Fatalf("restart fixture = %+v", c)
			}
			o.Stop()
			blocks := newFakeBlocks()
			panel := newFakePanel("allow")
			next := verdictPolicy(1, panel)
			next.DryRun = dry
			next.Allows = func(admission.Candidate) bool { return false }
			o, _, _ = policyOwner(t, f, blocks, next)
			turn(t, o)
			if c := candidate(t, o, id); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 {
				t.Fatalf("disabled persisted pick = %+v", c)
			}
			checks, applies := blocks.calls()
			asked, _, _, _ := panel.state()
			if len(asked) != 0 || len(checks) != 0 || len(applies) != 0 || len(blocks.snapshots) != 0 || liveUsed(t, o) != 0 || f.db.DryRunBlocksCount() != 0 {
				t.Fatal("disabled persisted work reached an execution or forecast side effect")
			}
			var notices []admission.NoticeRecord
			if err := o.do(func() (err error) { notices, err = o.ledger.PendingNotices(); return err }); err != nil || len(notices) != 0 {
				t.Fatalf("disabled persisted work raised notices: %+v, %v", notices, err)
			}
		})
	}
}

// The opt-out check precedes challenge comparison and unsupported-kind
// endings too, not only the block-IP batch.
func TestOwnerDisableCoversPreviewAndUnmodelledKinds(t *testing.T) {
	for _, dry := range []bool{false, true} {
		t.Run(map[bool]string{false: "preview", true: "forecast"}[dry], func(t *testing.T) {
			withLiveExecution(t, false)
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			policy := validPolicy(1)
			policy.DryRun = dry
			policy.Allows = func(admission.Candidate) bool { return false }
			o, _, _ := policyOwner(t, f, blocks, policy)
			promotion, _ := queuedKind(t, o, p, f.host, admission.SeverityHigh, "192.0.2.20", admission.KindPromote)
			challenge, _ := queuedKind(t, o, p, f.host, admission.SeverityHigh, "192.0.2.21", admission.KindChallenge)
			prefix, err := admission.CanonicalPrefix("198.51.100.0/24", admission.Caps{IPv6: true})
			if err != nil {
				t.Fatal(err)
			}
			subnet, _ := queuedTarget(t, o, p, f.host, admission.SeverityHigh, "198.51.100.7", admission.KindBlockSubnet, prefix)
			turn(t, o)
			for _, id := range []admission.CandidateID{promotion, challenge, subnet} {
				if c := candidate(t, o, id); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 {
					t.Fatalf("disabled kind = %+v", c)
				}
			}
			checks, applies := blocks.calls()
			if len(checks) != 0 || len(applies) != 0 || len(blocks.snapshots) != 0 || liveUsed(t, o) != 0 || len(pendingAudit(t, o)) != 0 {
				t.Fatal("disabled kind spent capacity or reached the engine")
			}
		})
	}
}
