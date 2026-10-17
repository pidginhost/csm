//go:build linux

package firewall_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// The boots an engine kill-point test runs in.
const (
	killBootA = "3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f"
	killBootB = "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b"
)

// killLedger is the admission ledger an engine kill-point test runs its
// batch through, opened again at every restart as a new process opens it,
// and the host's boot: its ID and the wall time it started.
type killLedger struct {
	t        *testing.T
	dir      string
	at       time.Time
	boot     string
	bootAt   time.Time
	reg      *admission.Registry
	producer *admission.Producer
	db       *store.DB
	l        *store.AdmissionLedger
}

func newKillLedger(t *testing.T, dir string, at time.Time) *killLedger {
	t.Helper()
	reg, err := admission.NewRegistry(func(check string) (string, admission.Policy, bool) {
		return check, admission.Policy{Family: admission.FamilySSH, Basis: admission.BasisLocal}, check == "ssh_brute"
	})
	if err != nil {
		t.Fatal(err)
	}
	producer, err := reg.Register(admission.ProducerSpec{ID: "sshd_log", Entry: admission.EntryScan, Observation: admission.ObservationLogCursor, Checks: []string{"ssh_brute"}})
	if err != nil {
		t.Fatal(err)
	}
	reg.Seal()
	k := &killLedger{t: t, dir: dir, at: at, boot: killBootA, bootAt: at.Add(-time.Hour), reg: reg, producer: producer}
	k.open()
	k.tick(at)
	if err = k.l.SetCeiling(2000); err != nil {
		t.Fatal(err)
	}
	if err = k.l.RefreshInventory(admission.InventoryObservation{}); err != nil {
		t.Fatal(err)
	}
	return k
}

func (k *killLedger) open() {
	k.t.Helper()
	db, err := store.Open(k.dir)
	if err != nil {
		k.t.Fatal(err)
	}
	k.db = db
	k.t.Cleanup(func() { _ = db.Close() })
	if k.l, err = store.OpenAdmissionLedger(db, k.reg); err != nil {
		k.t.Fatal(err)
	}
}

// reading is the host clock at wall.
func (k *killLedger) reading(wall time.Time) admission.ClockReading {
	return admission.ClockReading{Wall: wall, BootID: k.boot, SinceBoot: wall.Sub(k.bootAt)}
}

func (k *killLedger) tick(wall time.Time) {
	k.t.Helper()
	if result, err := k.l.Tick(k.reading(wall)); err != nil || result.Degraded {
		k.t.Fatalf("tick = %+v, %v", result, err)
	}
}

// engine starts a new engine over dir at wall in the current boot.
func (k *killLedger) engine(dir string, wall time.Time, kernel, keep map[string]time.Duration, kill firewall.KillPoint) (*firewall.Engine, func()) {
	k.t.Helper()
	return firewall.KillPointTestEngine(k.t, dir, wall, k.boot, wall.Sub(k.bootAt), kernel, keep, kill)
}

// ack delivers every pending audit row.
func (k *killLedger) ack() {
	k.t.Helper()
	rows, err := k.l.PendingAudit(int(admission.MaxAuditSlots))
	if err != nil {
		k.t.Fatal(err)
	}
	acks := make([]admission.AuditAck, 0, len(rows))
	for _, row := range rows {
		acks = append(acks, row.Ack())
	}
	if err = k.l.AckAudit(acks); err != nil {
		k.t.Fatal(err)
	}
}

// running queues a block of each address, reserves it until expires and
// records the batch as running, as the owner does before the engine runs
// it, and returns the batch's members.
func (k *killLedger) running(addrs []string, expires time.Time) []firewall.BlockMember {
	k.t.Helper()
	episode, err := admission.ParseEpisodeID("00000000000000000000000000000001")
	if err != nil {
		k.t.Fatal(err)
	}
	var members []firewall.BlockMember
	var ids []admission.ActionID
	for _, addr := range addrs {
		target, err := admission.CanonicalAddress(addr, admission.Caps{IPv6: true})
		if err != nil {
			k.t.Fatal(err)
		}
		evidence, err := k.producer.Mint(admission.EvidenceInput{
			Check: "ssh_brute", FindingID: "0123456789abcdef", Severity: admission.SeverityHigh,
			Observation: admission.ObservationRef{Stream: "fixture", Cursor: "offset=" + addr, Version: 1},
			ObservedAt:  k.at, Parser: admission.ParserRef{Name: "fixture", Version: 1}, Target: target,
		})
		if err != nil {
			k.t.Fatal(err)
		}
		if _, err = k.l.PublishEvidence(evidence); err != nil {
			k.t.Fatal(err)
		}
		c, created, err := k.l.Enqueue(admission.CandidateRequest{Kind: admission.KindBlockIP, Target: target, Episode: episode, Generation: 1, Primary: evidence.ID()})
		if err != nil || !created {
			k.t.Fatalf("enqueue %s = %t, %v", addr, created, err)
		}
		id, err := c.ID()
		if err != nil {
			k.t.Fatal(err)
		}
		_, a, granted, err := k.l.Reserve(id, admission.LaneGeneral, expires)
		if err != nil || !granted {
			k.t.Fatalf("reserve %s = %t, %v", addr, granted, err)
		}
		ids = append(ids, a.Attempt.ID)
		members = append(members, firewall.BlockMember{Action: string(a.Attempt.ID), IP: addr, Reason: "CSM auto-block: ssh_brute", ExpiresAt: expires})
	}
	if _, granted, err := k.l.ExecuteBatch(ids); err != nil || !granted {
		k.t.Fatalf("recording the batch as running = %t, %v", granted, err)
	}
	return members
}

// restart closes the database and opens it again, then settles what the
// stopped process left, as the owner's start does before the firewall
// starts. A reboot also starts a new boot a minute before wall.
func (k *killLedger) restart(wall time.Time, reboot bool) (failed, unknown int) {
	k.t.Helper()
	if err := k.db.Close(); err != nil {
		k.t.Fatal(err)
	}
	if reboot {
		k.boot, k.bootAt = killBootB, wall.Add(-time.Minute)
	}
	k.open()
	k.tick(wall)
	failed, unknown, err := k.l.Settle()
	if err != nil {
		k.t.Fatal(err)
	}
	return failed, unknown
}

func (k *killLedger) attempt(id string) admission.AttemptRecord {
	k.t.Helper()
	a, err := k.l.Attempt(admission.ActionID(id))
	if err != nil {
		k.t.Fatal(err)
	}
	return a
}

func killRows(t *testing.T, path string) map[string]firewall.BlockedEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state firewall.FirewallState
	if err = json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	rows := map[string]firewall.BlockedEntry{}
	for _, row := range state.Blocked {
		if _, duplicate := rows[row.IP]; duplicate {
			t.Fatalf("scenario contains duplicate rows for %s", row.IP)
		}
		rows[row.IP] = row
	}
	return rows
}

// gate starts the engine as the daemon's startup does before Apply: the
// saved admission clock sets its lease floor, every row whose attempt the
// ledger has not proven applied is marked, then the rows of settled
// attempts go. Apply rebuilds the table, so the kernel then holds what it
// restores.
func gate(t *testing.T, k *killLedger, wall time.Time, e *firewall.Engine, path string, apply func()) (unproven, settled []string) {
	t.Helper()
	e.SetBootClock(func() (string, time.Duration, error) {
		return k.boot, wall.Sub(k.bootAt), nil
	})
	clock, clockErr := store.ReadAdmissionClock(k.db)
	if clockErr == nil && clock.Initialized() {
		// Advance validates the reading. Proven uses the saved clock,
		// including its high-water mark on a new boot, as startup does.
		if _, _, err := clock.Advance(k.reading(wall)); err == nil {
			e.SetLeaseFloor(clock.Proven(k.reading(wall)))
		}
	}
	state, err := firewall.LoadState(filepath.Dir(filepath.Dir(path)))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, row := range state.Blocked {
		if row.ActionID != "" {
			ids = append(ids, row.ActionID)
		}
	}
	unproven, err = store.ReadUnprovenBlockActions(k.db, ids)
	if err != nil {
		e.SetBlockActionsUnproven(err)
		apply()
		return nil, nil
	}
	if len(unproven) > 0 {
		if _, err = e.MarkBlockActionsUnverified(unproven); err != nil {
			t.Fatal(err)
		}
		if settled, err = store.ReadSettledBlockActions(k.db, unproven); err != nil {
			t.Fatal(err)
		}
		if len(settled) > 0 {
			if _, err = e.RemoveBlockActionRows(settled); err != nil {
				t.Fatal(err)
			}
		}
	}
	apply()
	return unproven, settled
}

// A reboot with a wall clock behind the saved admission high-water mark
// must not lengthen a timed block. No engine checkpoint exists in this case.
func TestBlockStartupLeaseFloorOnANewBoot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Millisecond)
		dir := t.TempDir()
		stateDir := filepath.Join(dir, "firewall")
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(stateDir, "state.json")
		data, err := json.Marshal(firewall.FirewallState{Blocked: []firewall.BlockedEntry{
			{IP: "192.0.2.80", Reason: "operator", ExpiresAt: at.Add(time.Hour)},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		k := newKillLedger(t, dir, at)
		k.tick(at.Add(20 * time.Minute))
		wall := at.Add(-10 * time.Minute)
		k.boot, k.bootAt = killBootB, wall.Add(-time.Minute)
		kernel := map[string]time.Duration{}
		e, apply := k.engine(stateDir, wall, kernel, nil, "")
		gate(t, k, wall, e, path, apply)
		if len(kernel) != 1 || kernel["192.0.2.80"] != 40*time.Minute || !e.LeaseNow().Equal(at.Add(20*time.Minute)) {
			t.Fatalf("new boot renewed the lease: %v, clock %v", kernel, e.LeaseNow())
		}
	})
}

// A committed outcome survives a kill between the two ledger finishes.
// Only that member is restored; kernel membership proves neither outcome.
func TestBlockStartupRestoresOnlyTheFinishedMember(t *testing.T) {
	for _, reboot := range []bool{false, true} {
		t.Run(fmt.Sprintf("reboot=%t", reboot), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				at := time.Now().UTC().Truncate(time.Millisecond)
				dir := t.TempDir()
				stateDir := filepath.Join(dir, "firewall")
				if err := os.MkdirAll(stateDir, 0o700); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(stateDir, "state.json")
				if err := os.WriteFile(path, []byte(`{"blocked":[]}`), 0o600); err != nil {
					t.Fatal(err)
				}
				k := newKillLedger(t, dir, at)
				members := k.running([]string{"203.0.113.80", "2001:db8::80"}, at.Add(time.Hour))
				kernel := map[string]time.Duration{}
				e, _ := k.engine(stateDir, at, kernel, map[string]time.Duration{members[0].IP: time.Hour, members[1].IP: time.Hour}, "")
				results, err := e.ApplyBlockBatch(members)
				if err != nil || len(results) != 2 || results[0].Effect != firewall.BlockApplied || results[1].Effect != firewall.BlockApplied {
					t.Fatalf("batch = %v, %v", results, err)
				}
				const point = "after the first committed outcome"
				func() {
					defer func() {
						if got := recover(); got != point {
							t.Fatalf("kill point = %v, want %s", got, point)
						}
					}()
					if _, _, err := k.l.Finish(admission.ActionID(members[0].Action), admission.DispositionApplied); err != nil {
						t.Fatal(err)
					}
					panic(point)
				}()
				if reboot {
					clear(kernel)
				}
				restart := at.Add(time.Minute)
				if failed, unknown := k.restart(restart, reboot); failed != 0 || unknown != 1 {
					t.Fatalf("mixed batch settled %d failed, %d unknown", failed, unknown)
				}
				e, apply := k.engine(stateDir, restart, kernel, nil, "")
				unproven, settled := gate(t, k, restart, e, path, apply)
				if !slices.Equal(unproven, []string{members[1].Action}) || len(settled) != 0 || len(kernel) != 1 || kernel[members[0].IP] != 59*time.Minute {
					t.Fatalf("mixed restart: held %v, settled %v, kernel %v", unproven, settled, kernel)
				}
				if a := k.attempt(members[0].Action); a.State != admission.StateVerified || a.Disposition != admission.DispositionApplied {
					t.Fatalf("committed outcome changed: %+v", a)
				}
				if a := k.attempt(members[1].Action); a.State != admission.StateUnknown || a.Retired {
					t.Fatalf("uncommitted outcome was inferred: %+v", a)
				}
			})
		})
	}
}

// Kill points inside the engine's batch (spec 5.4, 5.5, 7.1 "Legacy
// crash"; design P9, P10): a batch of an IPv4 and an IPv6 address is
// stopped at each step of ApplyBlockBatch. After the atomic batch the
// kernel keeps the first and loses the second before readback; a rejected
// batch applies neither. The ledger and a new engine then start as a daemon
// starts them, after a process restart that leaves the kernel as it was or
// after a reboot that empties it, with the ledger readable or first
// unreadable. With the ledger readable both attempts are unknown; every row
// they wrote is held back, neither address is restored, and a new block of
// an address with a row waits as pending recovery. Once the expiry passes,
// retirement finds nothing of either, removes their rows and retires them;
// a further start restores no unresolved action and removes no further row.
func TestBlockBatchConvergesAfterAKillInTheEngine(t *testing.T) {
	const kept, lost, operator = "203.0.113.70", "2001:db8::71", "198.51.100.70"
	for _, tc := range []struct {
		kill firewall.KillPoint
		// rows and marked are the batch's rows the kill leaves in the
		// state file, and how many of them are marked unverified; sent is
		// whether the kernel took the batch.
		rows, marked int
		sent         bool
	}{
		{firewall.KillBeforeIntent, 0, 0, false},
		{firewall.KillBeforeKernel, 2, 0, false},
		{firewall.KillBeforeReadback, 2, 0, true},
		{firewall.KillBeforeMark, 2, 0, true},
		{firewall.KillAfterMark, 2, 1, true},
		{firewall.KillBeforeRestore, 2, 0, false},
		{firewall.KillAfterRestore, 0, 0, false},
	} {
		for _, reboot := range []bool{false, true} {
			for _, unreadable := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/reboot=%t/unreadable=%t", tc.kill, reboot, unreadable), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						at := time.Now().UTC().Round(0)
						dir := t.TempDir()
						stateDir := filepath.Join(dir, "firewall")
						if err := os.MkdirAll(stateDir, 0o700); err != nil {
							t.Fatal(err)
						}
						statePath := filepath.Join(stateDir, "state.json")
						if err := os.WriteFile(statePath, []byte(`{"blocked":[{"ip":"`+operator+`","reason":"operator"}]}`), 0o600); err != nil {
							t.Fatal(err)
						}
						k := newKillLedger(t, dir, at)
						expires := at.Add(time.Hour)
						members := k.running([]string{kept, lost}, expires)
						kernel := map[string]time.Duration{operator: 0}
						engine, _ := k.engine(stateDir, at, kernel, map[string]time.Duration{kept: time.Hour}, tc.kill)
						func() {
							defer func() {
								if got := recover(); got != tc.kill {
									t.Fatalf("kill point = %v, want %v", got, tc.kill)
								}
							}()
							_, _ = engine.ApplyBlockBatch(members)
						}()
						rows := killRows(t, statePath)
						marked := 0
						for _, m := range members {
							if rows[m.IP].Unverified {
								marked++
							}
						}
						if len(rows) != 1+tc.rows || marked != tc.marked {
							t.Fatalf("after the kill the state holds %+v; want %d batch rows, %d marked", rows, tc.rows, tc.marked)
						}
						wantKernel := map[string]time.Duration{operator: 0}
						if tc.sent {
							wantKernel[kept] = time.Hour
						}
						if !maps.Equal(kernel, wantKernel) {
							t.Fatalf("after the kill the kernel holds %v; want %v", kernel, wantKernel)
						}
						if reboot {
							clear(kernel)
						}

						restart := at.Add(time.Minute)
						if unreadable {
							if reboot {
								k.boot, k.bootAt = killBootB, restart.Add(-time.Minute)
							}
							pendingBefore, auditErr := k.l.PendingAudit(int(admission.MaxAuditSlots))
							if auditErr != nil {
								t.Fatal(auditErr)
							}
							if err := k.db.Close(); err != nil {
								t.Fatal(err)
							}
							degradedEngine, apply := k.engine(stateDir, restart, kernel, nil, "")
							gate(t, k, restart, degradedEngine, statePath, apply)
							if degradedEngine.BlockActionsUnproven() == nil || !maps.Equal(rows, killRows(t, statePath)) {
								t.Fatal("unreadable ledger was not reported or changed saved rows")
							}
							want := map[string]time.Duration{operator: 0}
							for _, m := range members {
								if row, ok := rows[m.IP]; ok && !row.Unverified {
									want[m.IP] = expires.Sub(restart)
								}
							}
							if !maps.Equal(kernel, want) {
								t.Fatalf("unreadable startup installed %v; want %v", kernel, want)
							}
							k.open()
							pendingAfter, auditErr := k.l.PendingAudit(int(admission.MaxAuditSlots))
							if auditErr != nil || !reflect.DeepEqual(pendingAfter, pendingBefore) {
								t.Fatalf("fallback changed the audit outbox: %v, %v", pendingAfter, auditErr)
							}
							for _, m := range members {
								if a := k.attempt(m.Action); a.State != admission.StateExecuting {
									t.Fatalf("fallback inferred an outcome: %+v", a)
								}
							}
						}
						if failed, unknown := k.restart(restart, reboot); failed != 0 || unknown != 2 {
							t.Fatalf("settled %d failed, %d unknown; want 2 unknown", failed, unknown)
						}
						engine, seed := k.engine(stateDir, restart, kernel, nil, "")
						unproven, settled := gate(t, k, restart, engine, statePath, seed)
						if len(unproven) != tc.rows-tc.marked || len(settled) != 0 {
							t.Fatalf("the gate found %v unproven and %v settled; want every batch row held", unproven, settled)
						}
						rows = killRows(t, statePath)
						for _, m := range members {
							a := k.attempt(m.Action)
							if a.State != admission.StateUnknown || a.Retired {
								t.Fatalf("%s after the restart = %+v; want unknown", m.IP, a)
							}
							if row, ok := rows[m.IP]; ok != (tc.rows > 0) || (ok && (!row.Unverified || row.ActionID != m.Action)) {
								t.Fatalf("%s row after the gate = %+v (present %t)", m.IP, row, ok)
							}
							if _, restored := kernel[m.IP]; restored || engine.IsBlocked(m.IP) {
								t.Fatalf("a restart restored %s, whose outcome is unknown", m.IP)
							}
						}
						if _, ok := kernel[operator]; !ok || len(kernel) != 1 {
							t.Fatalf("the restart restored %v; want only the operator block", kernel)
						}
						// A new block of an address a held row names waits.
						next := firewall.BlockMember{Action: "act_" + strings.Repeat("7f", 16), IP: kept, Reason: "CSM auto-block: ssh_brute", ExpiresAt: restart.Add(time.Hour)}
						checks, err := engine.CheckBlockBatchEffects([]firewall.BlockMember{next})
						if err != nil || len(checks) != 1 || (checks[0].Refusal == firewall.BlockRefusedPending) != (tc.rows > 0) {
							t.Fatalf("a new block of %s = %+v, %v; want pending recovery while a held row names it", kept, checks, err)
						}

						// After the expiry nothing of either remains: their rows go,
						// then the ledger retires them.
						after := expires.Add(time.Second)
						k.tick(after)
						k.ack()
						actions := make([]firewall.BlockAction, len(members))
						for i, m := range members {
							actions[i] = firewall.BlockAction{Action: m.Action, IP: m.IP}
						}
						clearOf, err := engine.RetireBlockActions(actions)
						if err != nil || !slices.Equal(clearOf, []bool{true, true}) {
							t.Fatalf("retirement found %v, %v; want both clear", clearOf, err)
						}
						if rows = killRows(t, statePath); len(rows) != 1 {
							t.Fatalf("retirement kept rows %+v", rows)
						}
						for _, m := range members {
							if _, retired, granted, err := k.l.RetireUnproven(admission.ActionID(m.Action)); err != nil || !granted || !retired.Retired {
								t.Fatalf("retiring %s = %+v, %t, %v", m.IP, retired, granted, err)
							}
						}
						k.ack()

						again := after.Add(time.Minute)
						if failed, unknown := k.restart(again, false); failed != 0 || unknown != 0 {
							t.Fatalf("a further start settled %d failed, %d unknown", failed, unknown)
						}
						engine, seed = k.engine(stateDir, again, kernel, nil, "")
						if unproven, settled = gate(t, k, again, engine, statePath, seed); len(unproven) != 0 || len(settled) != 0 {
							t.Fatalf("a further start found %v unproven, %v settled", unproven, settled)
						}
						if _, ok := kernel[operator]; !ok || len(kernel) != 1 {
							t.Fatalf("a further start restored %v", kernel)
						}
					})
				})
			}
		}
	}
}
