package store

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// importAt is an import the firewall lists at target, expiring after ttl:
// a stamped legacy block with no record of its own.
func (f *ledgerFixture) importAt(n byte, target string, ttl time.Duration) admission.EvictionVictim {
	f.t.Helper()
	return admission.EvictionVictim{Action: admission.ActionID("eff_" + strings.Repeat(fmt.Sprintf("%02x", n), 16)), Target: f.target(target),
		Tier: admission.ImportTier, Partition: admission.PartitionGeneral, ExpiresAt: f.wall.Add(ttl)}
}

// fillGeneral sizes the set so that n general occupants, records or
// imports, fill its general partition and one reserved slot stays free,
// and hands the ledger imports as the firewall lists them.
func (f *ledgerFixture) fillGeneral(n int, imports ...admission.EvictionVictim) {
	f.t.Helper()
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 3 + n + 1, Unclaimed: 3, General: len(imports)})
	f.l.SetImports(imports)
}

// pool is the victim pool the ledger builds from its records and imports.
func (f *ledgerFixture) pool(imports []admission.EvictionVictim) []admission.EvictionVictim {
	f.t.Helper()
	var pool []admission.EvictionVictim
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		var poolErr error
		pool, _, poolErr = victimPool(tx, f.wall, nil, imports)
		return poolErr
	}); err != nil {
		f.t.Fatal(err)
	}
	return pool
}

// An import fills a general slot and yields to strictly higher work (spec
// 6: known automatic imports are (C2, High) victims). The reservation
// names it in the block's record, which takes its general slot, and no
// other block can claim it while that record does. Work at or below its
// tier waits, and the ledger reopens with the claim.
func TestAdmissionLedgerReserveClaimsAnImport(t *testing.T) {
	f := liveLedgerFixture(t)
	imp := f.importAt(1, "192.0.2.60", time.Hour)
	f.fillGeneral(1, imp)
	_, a, _, err := f.l.Reserve(f.queuedWith("192.0.2.11", admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	member, _ := f.effectOf(a)
	if member.Victim != (admission.EffectRef{Action: imp.Action, ExpiresAt: imp.ExpiresAt}) || member.Partition != admission.PartitionGeneral {
		t.Fatalf("member record %+v", member)
	}
	if _, tally, _ := f.effectRecords(); tally != (admission.EffectTally{General: 1}) {
		t.Fatalf("tally %+v; an import holds no record", tally)
	}
	if pool := f.pool([]admission.EvictionVictim{imp}); len(pool) != 0 {
		t.Fatalf("a claimed import stayed in the pool: %+v", pool)
	}
	for name, sev := range map[string]admission.Severity{"another critical block": admission.SeverityCritical, "the import's tier": admission.SeverityHigh} {
		id := f.queuedWith(map[string]string{"another critical block": "192.0.2.12", "the import's tier": "192.0.2.13"}[name], sev)
		before := f.snapshot()
		_, _, _, err = f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
		wantLedgerReason(t, name, err, admission.ReasonSetFull)
		if !reflect.DeepEqual(before, f.snapshot()) {
			t.Fatalf("%s: a refused reservation changed the ledger", name)
		}
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen with an import claim: %v", err)
	}
}

// A record below the import's tier goes first: the lowest tier is evicted
// first, whatever holds it.
func TestAdmissionLedgerEvictsALowerRecordBeforeAnImport(t *testing.T) {
	f := liveLedgerFixture(t)
	imp := f.importAt(1, "192.0.2.60", time.Minute)
	f.fillGeneral(2, imp)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	if a := f.evicting("192.0.2.11", low); a.Attempt.ID == "" {
		t.Fatal("no reservation")
	}
}

// The schedule funds strictly higher work with an import and leaves the
// rest waiting as set_full.
func TestAdmissionLedgerScheduleFundsWorkWithAnImport(t *testing.T) {
	f := liveLedgerFixture(t)
	f.fillGeneral(1, f.importAt(1, "192.0.2.60", time.Hour))
	high := f.queuedWith("192.0.2.20", admission.SeverityHigh)
	critical := f.queuedWith("192.0.2.21", admission.SeverityCritical)
	picks, err := f.l.Schedule(allSlots, nil)
	if err != nil || len(picks) != 1 || picks[0].ID != critical {
		t.Fatalf("picks %+v, %v; want only the critical block", picks, err)
	}
	if c := f.candidateOf(high); c.Reason != admission.ReasonSetFull {
		t.Fatalf("the import's tier waits as %s, want set_full", c.Reason)
	}
}

// The intent names the import with its address, so the batch can remove
// it. An import the firewall no longer lists by execution leaves the
// block without a victim.
func TestAdmissionLedgerIntentNamesAnImport(t *testing.T) {
	for _, change := range []string{"listed", "missing", "another name", "another expiry"} {
		t.Run(change, func(t *testing.T) {
			f := liveLedgerFixture(t)
			imp := f.importAt(1, "192.0.2.60", time.Hour)
			f.fillGeneral(1, imp)
			_, a, _, err := f.l.Reserve(f.queuedWith("192.0.2.11", admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(2*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			want := admission.Victim{Action: imp.Action, Target: imp.Target, ExpiresAt: imp.ExpiresAt}
			if change != "listed" {
				current := imp
				switch change {
				case "missing":
					f.l.SetImports(nil)
				case "another name":
					current.Action = f.importAt(2, "192.0.2.60", time.Hour).Action
					f.l.SetImports([]admission.EvictionVictim{current})
				case "another expiry":
					current.ExpiresAt = current.ExpiresAt.Add(time.Minute)
					f.l.SetImports([]admission.EvictionVictim{current})
				}
				want = admission.Victim{}
			}
			intents, _, err := f.l.ExecuteBatch([]admission.ActionID{a.Attempt.ID})
			if err != nil || len(intents) != 1 || intents[0].Victim != want || f.intents()[a.Attempt.ID].Victim != want {
				t.Fatalf("intents %+v %v, want victim %+v", intents, err, want)
			}
			if member, _ := f.effectOf(a); member.Victim != (admission.EffectRef{Action: want.Action, ExpiresAt: want.ExpiresAt}) {
				t.Fatalf("member record %+v", member)
			}
			if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("reopen: %v", err)
			}
		})
	}
}

// An import's claim ends with its block's outcome and changes no other
// record: a verified block keeps no claim and a failed one leaves, so the
// import is the firewall's to list again; an unknown outcome keeps the
// claim while the block's record lasts.
func TestAdmissionLedgerImportClaimEndsWithTheOutcome(t *testing.T) {
	for _, tc := range []struct {
		name    string
		d       admission.Disposition
		v       admission.VictimOutcome
		claimed bool
	}{
		{"removed", admission.DispositionApplied, admission.VictimRemoved, false},
		{"spared", admission.DispositionApplied, admission.VictimSpared, false},
		{"failed", admission.DispositionFailed, admission.VictimSpared, false},
		{"unknown", admission.DispositionUnknown, admission.VictimUnproven, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := liveLedgerFixture(t)
			imp := f.importAt(1, "192.0.2.60", time.Hour)
			f.fillGeneral(1, imp)
			_, a, _, err := f.l.Reserve(f.queuedWith("192.0.2.11", admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(2*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = f.l.ExecuteBatch([]admission.ActionID{a.Attempt.ID}); err != nil {
				t.Fatal(err)
			}
			if _, _, err = f.l.FinishEviction(a.Attempt.ID, tc.d, tc.v, 0); err != nil {
				t.Fatal(err)
			}
			if pool := f.pool([]admission.EvictionVictim{imp}); (len(pool) == 0) != tc.claimed {
				t.Fatalf("pool %+v; claimed %t", pool, tc.claimed)
			}
			want := admission.EffectTally{General: 1}
			if tc.d == admission.DispositionFailed {
				want = admission.EffectTally{}
			}
			if _, tally, _ := f.effectRecords(); tally != want {
				t.Fatalf("tally %+v, want %+v", tally, want)
			}
			if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("reopen: %v", err)
			}
		})
	}
}

// The ledger takes only the imports the firewall can list, and only
// until they expire: anything else handed over as one funds no work.
func TestAdmissionLedgerIgnoresMalformedImports(t *testing.T) {
	for name, mutate := range map[string]func(*admission.EvictionVictim){
		"a lower tier": func(v *admission.EvictionVictim) {
			v.Tier = admission.Tier{Class: admission.ClassC1, Severity: admission.SeverityWarning}
		},
		"an expired import": func(v *admission.EvictionVictim) { v.ExpiresAt = v.ExpiresAt.Add(-2 * time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			f := liveLedgerFixture(t)
			bad := f.importAt(1, "192.0.2.60", time.Hour)
			mutate(&bad)
			f.fillGeneral(1, bad)
			_, _, _, err := f.l.Reserve(f.queuedWith("192.0.2.11", admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(time.Hour))
			wantLedgerReason(t, name, err, admission.ReasonSetFull)
		})
	}
}

// Opening proves an import claim as far as the block's own record can: it
// outranks the import tier.
func TestAdmissionLedgerOpenProvesImportClaims(t *testing.T) {
	for name, mutate := range map[string]func(*admission.EffectRecord){
		"not above the import tier": func(r *admission.EffectRecord) { r.Tier = admission.ImportTier },
		"a reserved import slot": func(r *admission.EffectRecord) {
			r.Partition, r.Lane = admission.PartitionReserved, admission.LaneDirect
			r.Direct, r.Tier = true, admission.Tier{Class: admission.ClassC3, Severity: admission.SeverityHigh}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := liveLedgerFixture(t)
			f.fillGeneral(1, f.importAt(1, "192.0.2.60", time.Hour))
			_, a, _, err := f.l.Reserve(f.queuedWith("192.0.2.11", admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(2*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			member, _ := f.effectOf(a)
			mutate(&member)
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
				putEffectForTest(t, tx, member)
				if member.Partition == admission.PartitionReserved {
					return putEffectTally(tx, admission.EffectTally{Reserved: 1})
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err = OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("opened: %v", err)
			}
		})
	}
}

// Claim endings must not look for an import record, including a delayed
// outcome whose only remaining claim is in its intent. Every ending is
// idempotent and preserves the tally on reopen.
func TestAdmissionLedgerImportClaimEveryEnding(t *testing.T) {
	for _, ending := range []string{"removed", "spared", "failed", "existing", "settle-reserved", "settle-executing", "retire-unknown"} {
		for _, swept := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/swept=%t", ending, swept), func(t *testing.T) {
				f := liveLedgerFixture(t)
				imp := f.importAt(1, "192.0.2.60", 3*time.Hour)
				f.fillGeneral(1, imp)
				_, a, _, err := f.l.Reserve(f.queuedWith("192.0.2.11", admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				if ending != "settle-reserved" {
					if _, _, err = f.l.ExecuteBatch([]admission.ActionID{a.Attempt.ID}); err != nil {
						t.Fatal(err)
					}
				}
				if ending == "retire-unknown" {
					if _, _, err = f.l.FinishEviction(a.Attempt.ID, admission.DispositionUnknown, admission.VictimUnproven, 0); err != nil {
						t.Fatal(err)
					}
				}
				if ending == "retire-unknown" {
					f.ackAll()
				}
				if swept || ending == "retire-unknown" {
					f.tickAt(a.ExpiresAt)
					if _, found := f.effectOf(a); found {
						t.Fatal("expired member record survived its sweep")
					}
					if pool := f.pool([]admission.EvictionVictim{imp}); len(pool) != 1 || pool[0] != imp {
						t.Fatalf("swept member still claims the import: %+v", pool)
					}
				}
				reopened, err := OpenAdmissionLedger(f.db, f.reg)
				if err != nil {
					t.Fatalf("before ending: %v", err)
				}
				finish := func() error {
					var endErr error
					switch ending {
					case "settle-reserved", "settle-executing":
						_, _, endErr = reopened.Settle()
					case "retire-unknown":
						_, _, _, endErr = f.l.RetireUnproven(a.Attempt.ID)
					case "existing":
						_, _, endErr = f.l.FinishExisting(a.Attempt.ID, admission.EffectLink{Effect: string(imp.Action), ExpiresAt: imp.ExpiresAt})
					default:
						d, v := admission.DispositionApplied, admission.VictimSpared
						switch ending {
						case "removed":
							v = admission.VictimRemoved
						case "failed":
							d = admission.DispositionFailed
						}
						_, _, endErr = f.l.FinishEviction(a.Attempt.ID, d, v, 0)
					}
					return endErr
				}
				if err = finish(); err != nil {
					t.Fatalf("ending an import claim: %v", err)
				}
				wantState := admission.StateFailed
				switch ending {
				case "removed", "spared":
					wantState = admission.StateVerified
				case "settle-executing", "retire-unknown":
					wantState = admission.StateUnknown
				}
				if got, readErr := f.l.Attempt(a.Attempt.ID); readErr != nil || got.State != wantState || got.Retired != (ending == "retire-unknown") {
					t.Fatalf("ending left attempt %+v, %v; want state %v", got, readErr, wantState)
				}
				before := f.snapshot()
				if err = finish(); err != nil || !reflect.DeepEqual(before, f.snapshot()) {
					t.Fatalf("duplicate ending changed the ledger: %v", err)
				}
				claimed := ending == "settle-executing" && !swept
				pool := f.pool([]admission.EvictionVictim{imp})
				wantPool := []admission.EvictionVictim{}
				if !swept && (ending == "removed" || ending == "spared") {
					member, found := f.effectOf(a)
					if !found || !member.Verified() || member.Victim != (admission.EffectRef{}) {
						t.Fatalf("verified member kept its claim: %+v", member)
					}
					wantPool = append(wantPool, admission.EvictionVictim{Action: member.Action, Target: member.Target, Tier: member.Tier, Partition: member.Partition, ExpiresAt: member.ExpiresAt,
						Scope: member.Scope, Applied: member.Applied})
				}
				if !claimed {
					wantPool = append(wantPool, imp)
				}
				if len(pool) != len(wantPool) || (len(pool) > 0 && !reflect.DeepEqual(pool, wantPool)) {
					t.Fatalf("pool %+v, want %+v", pool, wantPool)
				}
				want := admission.EffectTally{}
				if !swept && (ending == "removed" || ending == "spared" || claimed) {
					want.General = 1
				}
				if _, tally, _ := f.effectRecords(); tally != want {
					t.Fatalf("tally %+v, want %+v", tally, want)
				}
				if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
					t.Fatalf("after ending: %v", err)
				}
			})
		}
	}
}

// Two well-formed member records cannot claim one import, even if their
// references disagree on its expiry. There is no victim record to prove
// this from the other end.
func TestAdmissionLedgerOpenRejectsDuplicateImportClaims(t *testing.T) {
	for _, changedExpiry := range []bool{false, true} {
		t.Run(fmt.Sprint(changedExpiry), func(t *testing.T) {
			f := liveLedgerFixture(t)
			imp := f.importAt(1, "192.0.2.60", time.Hour)
			f.fillGeneral(1, imp)
			_, first, _, err := f.l.Reserve(f.queuedWith("192.0.2.11", admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(2*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			f.l.SetOccupants(nil)
			_, second, _, err := f.l.Reserve(f.queuedWith("192.0.2.12", admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(2*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			a, _ := f.effectOf(first)
			b, _ := f.effectOf(second)
			b.Victim = a.Victim
			if changedExpiry {
				b.Victim.ExpiresAt = b.Victim.ExpiresAt.Add(time.Minute)
			}
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
				putEffectForTest(t, tx, b)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err = OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("opened duplicate import claims: %v", err)
			}
		})
	}
}

// Open checks the import claim against the execution intent while the
// member record exists; after its sweep the intent alone may name it.
func TestAdmissionLedgerImportIntentProof(t *testing.T) {
	for _, damage := range []string{"omit", "name", "expiry"} {
		t.Run(damage, func(t *testing.T) {
			f := liveLedgerFixture(t)
			imp := f.importAt(1, "192.0.2.60", time.Hour)
			f.fillGeneral(1, imp)
			_, a, _, err := f.l.Reserve(f.queuedWith("192.0.2.11", admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(2*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			ins, _, err := f.l.ExecuteBatch([]admission.ActionID{a.Attempt.ID})
			if err != nil || len(ins) != 1 {
				t.Fatalf("execute: %+v, %v", ins, err)
			}
			in := ins[0]
			switch damage {
			case "omit":
				in.Victim = admission.Victim{}
			case "name":
				in.Victim.Action = f.importAt(2, "192.0.2.60", time.Hour).Action
			case "expiry":
				in.Victim.ExpiresAt = in.Victim.ExpiresAt.Add(time.Minute)
			}
			data, err := in.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte(admissionIntentsBucket)).Put([]byte(a.Attempt.ID), data)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err = OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("opened a mismatched import intent: %v", err)
			}
		})
	}
}

// The import list is also evidence of occupied general slots. A lower
// count must not fund a replacement into an overfull partition, and a
// larger count still includes imports beyond the bounded victim list.
func TestAdmissionLedgerImportOccupancyCannotUnderstateTheList(t *testing.T) {
	for _, tc := range []struct{ count, listed, general int }{
		{0, 2, 1}, {1, 2, 1}, {2, 2, 1}, {3, 1, 2},
	} {
		for _, operation := range []string{"schedule", "wake", "reserve", "observe"} {
			t.Run(fmt.Sprintf("count=%d/%s", tc.count, operation), func(t *testing.T) {
				f := liveLedgerFixture(t)
				imports := []admission.EvictionVictim{f.importAt(1, "192.0.2.60", time.Hour), f.importAt(2, "192.0.2.61", time.Hour)}
				// The list may be shorter or longer than the reported count.
				f.l.SetOccupants(&admission.SetOccupancy{Limit: 4 + tc.general, Unclaimed: 3, General: tc.count})
				f.l.SetImports(imports[:tc.listed])
				id := f.queuedWith("192.0.2.11", admission.SeverityCritical)
				switch operation {
				case "schedule":
					if picks, err := f.l.Schedule(allSlots, nil); err != nil || len(picks) != 0 || f.candidateOf(id).Reason != admission.ReasonSetFull {
						t.Fatalf("overfull import partition funded picks %+v, %v", picks, err)
					}
				case "wake":
					if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall.Add(setRecheck)) {
						t.Fatalf("overfull import partition woke at %v, %v, %v", wake, ok, err)
					}
				default:
					before := f.snapshot()
					reserve := f.l.Reserve
					if operation == "observe" {
						reserve = f.l.Observe
					}
					_, _, _, err := reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
					wantLedgerReason(t, "overfull import partition", err, admission.ReasonSetFull)
					if !reflect.DeepEqual(before, f.snapshot()) {
						t.Fatal("refused work changed the ledger")
					}
				}
			})
		}
	}
}

// Wake, schedule and Observe share the import list. A preview claims no
// import, changes no effect record or tally, and cannot lend its claim to
// execution. Replacing or clearing the list changes the next decision.
func TestAdmissionLedgerImportWakeAndObserve(t *testing.T) {
	f := liveLedgerFixture(t)
	imp := f.importAt(1, "192.0.2.60", time.Hour)
	imports := []admission.EvictionVictim{imp}
	f.fillGeneral(1, imports...)
	imports[0].Tier = admission.Tier{Class: admission.ClassC3, Severity: admission.SeverityCritical}
	id := f.queuedWith("192.0.2.11", admission.SeverityCritical)
	before, tally, _ := f.effectRecords()
	beforeWake := f.snapshot()
	if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("listed import must wake funded work now: %v, %v, %v", wake, ok, err)
	}
	if !reflect.DeepEqual(beforeWake, f.snapshot()) {
		t.Fatal("wake wrote a claim")
	}
	if c, _, granted, err := f.l.Observe(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil || !granted || c.State != admission.StateObserved {
		t.Fatalf("funded import preview: %+v, %t, %v", c, granted, err)
	}
	if after, afterTally, _ := f.effectRecords(); !reflect.DeepEqual(after, before) || afterTally != tally {
		t.Fatalf("preview changed effects: %+v, %+v", after, afterTally)
	}
	if pool := f.pool([]admission.EvictionVictim{imp}); len(pool) != 1 || pool[0] != imp || len(f.intents()) != 0 {
		t.Fatalf("preview left an import claim or intent: %+v", pool)
	}
	id = f.queuedWith("192.0.2.12", admission.SeverityCritical)
	if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("preview consumed the import list: %v, %v, %v", wake, ok, err)
	}
	for _, replacement := range [][]admission.EvictionVictim{nil, {f.importAt(2, "192.0.2.12", time.Hour)}} {
		f.l.SetImports(replacement)
		if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall.Add(setRecheck)) {
			t.Fatalf("unusable imports woke work: %v, %v, %v", wake, ok, err)
		}
		_, _, _, err := f.l.Observe(id, admission.LaneGeneral, f.wall.Add(time.Hour))
		wantLedgerReason(t, "unusable import preview", err, admission.ReasonSetFull)
	}
	f.l.SetImports([]admission.EvictionVictim{imp})
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ins, _, err := f.l.ExecuteBatch([]admission.ActionID{a.Attempt.ID})
	if err != nil || len(ins) != 1 || ins[0].Victim.Action != imp.Action || ins[0].Victim.Target != imp.Target {
		t.Fatalf("fresh list did not supply the execution victim: %+v, %v", ins, err)
	}
}

// Import occupancy must not turn an invalid supplied count into a valid
// snapshot; the existing tally validation still rejects it atomically.
func TestAdmissionLedgerImportsDoNotHideInvalidOccupancy(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 5, General: -1})
	f.l.SetImports([]admission.EvictionVictim{f.importAt(1, "192.0.2.60", time.Hour)})
	id := f.queuedWith("192.0.2.11", admission.SeverityCritical)
	before := f.snapshot()
	_, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if !isCorrupt(err) || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatalf("invalid occupancy admitted work or changed the ledger: %v", err)
	}
}
