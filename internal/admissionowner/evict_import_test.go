package admissionowner

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// importOwner is an owner whose general partition holds one slot, taken
// by an import of 192.0.2.60, a stamped legacy block the engine lists, and
// a Critical block of 192.0.2.11 queued behind it. The engine applies the
// block with result.
func importOwner(t *testing.T, result firewall.BlockResult) (*Owner, *fakeBlocks, firewall.BlockImport, admission.CandidateID) {
	t.Helper()
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	imp := firewall.BlockImport{ID: "eff_" + strings.Repeat("ab", 16), IP: "192.0.2.60", ExpiresAt: f.host.wall.Add(time.Hour)}
	// Three slots, one held by an operator block and the general one by
	// the import.
	blocks.limit, blocks.temp, blocks.imported, blocks.imports = 3, 2, 1, []firewall.BlockImport{imp}
	o := f.start(executeOptions(f, blocks))
	high, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	blocks.set(func(b *fakeBlocks) { b.results["192.0.2.11"] = result })
	return o, blocks, imp, high
}

// A block strictly above the import tier takes the import's slot: the
// engine receives the import as the victim, and once its removal is
// proven the owner retires the import's row by its name, with no mark (a
// stamped row is never marked unverified).
func TestOwnerEvictsAnImport(t *testing.T) {
	o, blocks, imp, high := importOwner(t, firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimRemoved})
	turn(t, o)
	_, applies := blocks.calls()
	if len(applies) != 1 || len(applies[0]) != 1 || applies[0][0].Victim != (firewall.BlockVictim{Action: imp.ID, IP: imp.IP, ExpiresAt: imp.ExpiresAt}) {
		t.Fatalf("the engine ran %+v, want the import as the victim", applies)
	}
	if c := candidate(t, o, high); c.State != admission.StateVerified {
		t.Fatalf("the evicting block is %+v", c)
	}
	if retires := blocks.retireCalls(); len(retires) != 1 || len(retires[0]) != 1 || retires[0][0] != (firewall.BlockAction{Action: imp.ID, IP: imp.IP}) {
		t.Fatalf("retired %v, want the import's row", retires)
	}
	var marked [][]string
	blocks.set(func(b *fakeBlocks) { marked = b.marked })
	for _, ids := range marked {
		for _, id := range ids {
			if id == imp.ID {
				t.Fatalf("marked %v; an import's row is never marked", marked)
			}
		}
	}
}

// An import whose element the engine still holds when the owner retires
// it (a reload or restart restored its row) is a legacy block again: the
// owner forgets it rather than retrying every turn.
func TestOwnerForgetsAnImportStillEnforced(t *testing.T) {
	o, blocks, imp, _ := importOwner(t, firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimRemoved})
	blocks.set(func(b *fakeBlocks) { b.present[imp.IP] = true })
	turn(t, o)
	turn(t, o)
	if retires := blocks.retireCalls(); len(retires) != 1 {
		t.Fatalf("retired %v; want one try", retires)
	}
}

// Previews evict imports as execution would: strictly higher work is
// observed with the import's slot, work at the import's tier waits as
// set_full.
func TestOwnerPreviewsTheEvictionOfAnImport(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit, blocks.temp, blocks.imported = 3, 2, 1
	blocks.imports = []firewall.BlockImport{{ID: "eff_" + strings.Repeat("ab", 16), IP: "192.0.2.60", ExpiresAt: f.host.wall.Add(time.Hour)}}
	o := f.start(executeOptions(f, blocks))
	high, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	critical, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	turn(t, o)
	if c := candidate(t, o, critical); c.State != admission.StateObserved {
		t.Fatalf("a critical preview over an import = %+v", c)
	}
	if c := candidate(t, o, high); c.State != admission.StateQueued || c.Reason != admission.ReasonSetFull {
		t.Fatalf("a preview at the import's tier = %+v", c)
	}
	if _, applies := blocks.calls(); len(applies) != 0 || len(blocks.retireCalls()) != 0 {
		t.Fatalf("a preview reached the engine: %d applies", len(applies))
	}
}

// A previous turn's list cannot supply an execution victim after a
// failed read, an idle turn, a missing engine or a move to forecasting.
func TestOwnerDropsImportsWithTheSet(t *testing.T) {
	for _, mode := range []string{"read failure", "no work", "no engine", "forecast", "empty list"} {
		t.Run(mode, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			imp := firewall.BlockImport{ID: "eff_" + strings.Repeat("ab", 16), IP: "192.0.2.60", ExpiresAt: f.host.wall.Add(time.Hour)}
			blocks.limit, blocks.temp, blocks.imported, blocks.imports = 3, 2, 1, []firewall.BlockImport{imp}
			o, policies, _ := policyOwner(t, f, blocks, validPolicy(1))
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
			if mode == "read failure" || mode == "empty list" {
				queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.12")
			}
			if err := o.do(func() error {
				if err := o.readSet(); err != nil {
					return err
				}
				_, a, _, err := o.ledger.Reserve(id, admission.LaneGeneral, imp.ExpiresAt.Add(time.Hour))
				if err != nil {
					return err
				}
				switch mode {
				case "forecast":
					policies.publish(dryPolicy(2))
					if err = o.refreshPolicy(); err != nil {
						return err
					}
				case "read failure":
					blocks.set(func(b *fakeBlocks) { b.checkErr = errors.New("set unavailable") })
				case "no engine":
					o.opts.Blocks = func() BlockEngine { return nil }
				case "empty list":
					blocks.set(func(b *fakeBlocks) { b.imports = nil })
				}
				if mode != "forecast" {
					if err = o.readSet(); err != nil {
						return err
					}
				}
				if mode == "read failure" && o.setErr == nil {
					t.Error("failed read was not exercised")
				}
				ins, _, err := o.ledger.ExecuteBatch([]admission.ActionID{a.Attempt.ID})
				if err != nil || len(ins) != 1 || ins[0].Victim != (admission.Victim{}) {
					t.Errorf("stale import reached execution: %+v, %v", ins, err)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A retirement error is not proof that an import is still enforced: keep
// the cleanup request until a later successful answer.
func TestOwnerRetriesAnImportRetirementError(t *testing.T) {
	o, blocks, imp, _ := importOwner(t, firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimRemoved})
	blocks.set(func(b *fakeBlocks) { b.retireErr = errors.New("retirement unavailable") })
	turn(t, o)
	if got := o.Status().Owner.RetirementError; !strings.Contains(got, "retirement unavailable") {
		t.Fatalf("retirement error not reported: %q", got)
	}
	blocks.set(func(b *fakeBlocks) { b.retireErr = nil })
	turn(t, o)
	turn(t, o)
	calls := blocks.retireCalls()
	if len(calls) != 2 {
		t.Fatalf("retirements %+v; want error and successful retry", calls)
	}
	for _, call := range calls {
		if len(call) != 1 || call[0] != (firewall.BlockAction{Action: imp.ID, IP: imp.IP}) {
			t.Fatalf("retired %+v; want only the import", call)
		}
	}
}

// repairingImportBlocks keeps the engine's state fault latched until a
// safe-state write succeeds, as a failed unknown-row write does after a
// batch with both applied and unknown members.
type repairingImportBlocks struct{ *fakeBlocks }

func (b repairingImportBlocks) MarkBlockActionsUnverified(ids []string) (int, error) {
	n, err := b.fakeBlocks.MarkBlockActionsUnverified(ids)
	if err == nil {
		b.set(func(f *fakeBlocks) { f.checkErr, f.retireErr = nil, nil })
	}
	return n, err
}

// An import-only cleanup must repair a shared state fault after its probe
// wait, even during dry run, without marking the import or proving an
// independent apply fault recovered.
func TestOwnerImportRetirementRepairsState(t *testing.T) {
	for _, dry := range []bool{false, true} {
		for _, applyHeld := range []bool{false, true} {
			t.Run(fmt.Sprintf("dry_run=%t/apply_held=%t", dry, applyHeld), func(t *testing.T) {
				withTestRegistry(t)
				f := newOwnerFixture(t)
				blocks := newFakeBlocks()
				policy := validPolicy(1)
				policy.DryRun = dry
				o, _, mono := policyOwner(t, f, blocks, policy)
				setOwnerHook(t, o, &o.opts.Blocks, func() BlockEngine { return repairingImportBlocks{blocks} })
				imp := firewall.BlockAction{Action: "eff_" + strings.Repeat("ab", 16), IP: "192.0.2.60"}
				fault := errors.Join(firewall.ErrBlockBatchState, errors.New("unknown row write failed"))
				applyFault := errors.New("earlier apply fault")
				blocks.set(func(b *fakeBlocks) { b.checkErr, b.retireErr = fault, fault })
				if err := o.do(func() error {
					o.evicted = []firewall.BlockAction{imp}
					if applyHeld {
						o.applyHold = applyFault
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				turn(t, o)
				if got := o.Status().Owner.RetirementError; !strings.Contains(got, "unknown row write failed") {
					t.Fatalf("state fault was not reported: %q", got)
				}
				mono.advance(firstProbeWait - time.Nanosecond)
				turn(t, o)
				if blocks.probes() != 0 || len(blocks.retireCalls()) != 1 {
					t.Fatal("import cleanup bypassed the state probe wait")
				}
				mono.advance(time.Nanosecond)
				turn(t, o)
				if got := o.Status().Owner.RetirementError; got != "" {
					t.Fatalf("import cleanup did not repair the state: %q", got)
				}
				calls := blocks.retireCalls()
				if len(calls) != 2 || len(calls[1]) != 1 || calls[1][0] != imp {
					t.Fatalf("retirements = %+v, want failure and successful retry", calls)
				}
				blocks.set(func(b *fakeBlocks) {
					wantRepairs := 1
					if !dry {
						// The live execution probe also checks the repaired state.
						wantRepairs++
					}
					if len(b.marked) != wantRepairs {
						t.Errorf("repair calls = %d, want %d", len(b.marked), wantRepairs)
					}
					for _, ids := range b.marked {
						if len(ids) != 0 {
							t.Errorf("repair marked rows: %v", ids)
						}
					}
				})
				if err := o.do(func() error {
					if len(o.evicted) != 0 {
						t.Errorf("retired import stayed pending: %v", o.evicted)
					}
					if applyHeld && !errors.Is(o.applyHold, applyFault) {
						t.Errorf("repair cleared the independent apply fault: %v", o.applyHold)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// The dry-run forecast still waits for space even when its snapshot
// lists an evictable import. It leaves live claims and budgets alone;
// returning to previews uses a fresh list and may observe higher work.
func TestOwnerForecastDoesNotEvictListedImports(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit, blocks.temp, blocks.imported = 3, 2, 1
	blocks.imports = []firewall.BlockImport{{ID: "eff_" + strings.Repeat("ab", 16), IP: "192.0.2.60", ExpiresAt: f.host.wall.Add(time.Hour)}}
	o, policies, _ := policyOwner(t, f, blocks, dryPolicy(1))
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	used := liveUsed(t, o)
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateDryRun || c.Attempts != 0 {
		t.Fatalf("forecast reserved or previewed its pick: %+v", c)
	}
	if fc := forecastOf(t, o); fc == nil || len(fc.entries) != 0 || fc.picks[admission.PredictSetFull] != 1 || fc.picks[admission.PredictCapacityAdmit] != 0 {
		t.Fatalf("forecast used an import as a victim: %+v", fc)
	}
	if liveUsed(t, o) != used {
		t.Fatal("forecast spent the live ceiling")
	}
	policies.publish(validPolicy(2))
	id, _ = queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.12")
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateObserved {
		t.Fatalf("preview failed to use the fresh import list: %+v", c)
	}
	if _, applies := blocks.calls(); len(applies) != 0 || len(blocks.retireCalls()) != 0 {
		t.Fatal("forecast or preview changed the firewall")
	}
}
