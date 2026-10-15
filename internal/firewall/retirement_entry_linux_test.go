//go:build linux

package firewall_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// The real ledger forgets a retired unknown, then a fresh engine seeds
// state after a wall rollback. Durable removal and both saved clocks are
// exercised together, including an injected pre-removal state image.
func TestRetirementEntryProofAfterHistoryRetires(t *testing.T) {
	const bootA = "0f5e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b"
	const bootB = "7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d"
	for _, boot := range []string{bootA, bootB} {
		for _, mode := range []string{"removed", "stale-with-floor", "stale-with-checkpoint"} {
			t.Run(boot+"/"+mode, func(t *testing.T) {
				at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
				dir := t.TempDir()
				db, err := store.Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
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
				ledger, err := store.OpenAdmissionLedger(db, reg)
				if err != nil {
					t.Fatal(err)
				}
				tick := func(wall time.Time) {
					t.Helper()
					if result, tickErr := ledger.Tick(admission.ClockReading{Wall: wall, BootID: bootA, SinceBoot: time.Hour + wall.Sub(at)}); tickErr != nil || result.Degraded {
						t.Fatalf("tick = %+v, %v", result, tickErr)
					}
				}
				ack := func() {
					t.Helper()
					rows, readErr := ledger.PendingAudit(int(admission.MaxAuditSlots))
					if readErr != nil {
						t.Fatal(readErr)
					}
					var acks []admission.AuditAck
					for _, row := range rows {
						acks = append(acks, row.Ack())
					}
					if ackErr := ledger.AckAudit(acks); ackErr != nil {
						t.Fatal(ackErr)
					}
				}
				tick(at)
				if err = ledger.SetCeiling(2000); err != nil {
					t.Fatal(err)
				}
				if err = ledger.RefreshInventory(admission.InventoryObservation{}); err != nil {
					t.Fatal(err)
				}
				target, err := admission.CanonicalAddress("203.0.113.95", admission.Caps{})
				if err != nil {
					t.Fatal(err)
				}
				evidence, err := producer.Mint(admission.EvidenceInput{
					Check: "ssh_brute", FindingID: "0123456789abcdef", Severity: admission.SeverityHigh,
					Observation: admission.ObservationRef{Stream: "fixture", Cursor: "offset=1", Version: 1},
					ObservedAt:  at, Parser: admission.ParserRef{Name: "fixture", Version: 1}, Target: target,
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = ledger.PublishEvidence(evidence); err != nil {
					t.Fatal(err)
				}
				episode, err := admission.ParseEpisodeID("00000000000000000000000000000001")
				if err != nil {
					t.Fatal(err)
				}
				c, created, err := ledger.Enqueue(admission.CandidateRequest{Kind: admission.KindBlockIP, Target: target, Episode: episode, Generation: 1, Primary: evidence.ID()})
				if err != nil || !created {
					t.Fatalf("enqueue = %t, %v", created, err)
				}
				id, err := c.ID()
				if err != nil {
					t.Fatal(err)
				}
				expires := at.Add(time.Hour)
				_, attempt, granted, err := ledger.Reserve(id, admission.LaneGeneral, expires)
				if err != nil || !granted {
					t.Fatalf("reserve = %t, %v", granted, err)
				}
				if _, _, _, err = ledger.Execute(attempt.Attempt.ID); err != nil {
					t.Fatal(err)
				}
				if _, _, err = ledger.Finish(attempt.Attempt.ID, admission.DispositionUnknown); err != nil {
					t.Fatal(err)
				}
				ack()
				stateDir := filepath.Join(dir, "firewall")
				if err = os.MkdirAll(stateDir, 0o700); err != nil {
					t.Fatal(err)
				}
				original, err := json.Marshal(firewall.FirewallState{Blocked: []firewall.BlockedEntry{
					{IP: "203.0.113.95", ActionID: string(attempt.Attempt.ID), ExpiresAt: expires},
					{IP: "203.0.113.96", Reason: "operator"},
				}})
				if err != nil {
					t.Fatal(err)
				}
				stateFile := filepath.Join(stateDir, "state.json")
				if err = os.WriteFile(stateFile, original, 0o600); err != nil {
					t.Fatal(err)
				}
				engine, _, checkpoint := firewall.RetirementTestEngine(t, stateDir, at, bootA, time.Hour)
				checkpoint()
				leaseFile := filepath.Join(stateDir, "lease.json")
				priorLease, err := os.ReadFile(leaseFile)
				if err != nil {
					t.Fatal(err)
				}
				tick(expires)
				engine.SetBootClock(func() (string, time.Duration, error) { return bootA, 2 * time.Hour, nil })
				engine.SetLeaseFloor(expires)
				clear, err := engine.RetireBlockActions([]firewall.BlockAction{{Action: string(attempt.Attempt.ID), IP: "203.0.113.95"}})
				if err != nil || len(clear) != 1 || !clear[0] {
					t.Fatalf("engine retirement = %v, %v", clear, err)
				}
				removed, readErr := os.ReadFile(stateFile)
				if readErr != nil {
					t.Fatal(readErr)
				}
				var state firewall.FirewallState
				if readErr = json.Unmarshal(removed, &state); readErr != nil || len(state.Blocked) != 1 || state.Blocked[0].IP != "203.0.113.96" {
					t.Fatalf("engine authorized retirement without durable removal: %+v, %v", state, readErr)
				}
				_, retired, granted, err := ledger.RetireUnproven(attempt.Attempt.ID)
				if err != nil || !granted || !retired.Retired || retired.State != admission.StateUnknown {
					t.Fatalf("ledger retirement = %+v, %t, %v", retired, granted, err)
				}
				ack()
				tick(at.Add(admission.HistoryTarget + time.Hour))
				if _, err = ledger.Attempt(attempt.Attempt.ID); err == nil {
					t.Fatal("entry proof did not actually retire the attempt's history")
				}
				if err = db.Close(); err != nil {
					t.Fatal(err)
				}
				db, err = store.Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = store.OpenAdmissionLedger(db, reg); err != nil {
					t.Fatal(err)
				}
				held, err := store.ReadUnprovenBlockActions(db, []string{string(attempt.Attempt.ID)})
				if err != nil || len(held) != 0 {
					t.Fatalf("forgotten history still supplied marking proof: %v, %v", held, err)
				}
				if mode != "removed" {
					// Fault injection: a stale, unmarked state image must also
					// be bounded by a persisted clock after history is gone.
					if err = os.WriteFile(stateFile, original, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "stale-with-floor" {
					// On a new boot, the old checkpoint cannot mask a missing ledger floor.
					if err = os.WriteFile(leaseFile, priorLease, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				behind := at.Add(-time.Hour)
				since := time.Hour
				if boot == bootA {
					since = admission.HistoryTarget + 2*time.Hour
				}
				restart, seed, _ := firewall.RetirementTestEngine(t, stateDir, behind, boot, since)
				if mode != "stale-with-checkpoint" {
					clock, readErr := store.ReadAdmissionClock(db)
					if readErr != nil {
						t.Fatal(readErr)
					}
					restart.SetLeaseFloor(clock.Proven(admission.ClockReading{Wall: behind, BootID: boot, SinceBoot: since}))
				}
				got := seed()
				left, present := got["203.0.113.96"]
				if len(got) != 1 || !present || left != 0 {
					t.Fatalf("restart restored forgotten unknown or lost operator row: %v", got)
				}
			})
		}
	}
}
