//go:build linux

package firewall_test

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// reserveAt queues a block of addr from evidence of severity and reserves
// it on the general lane until expires, as the owner does.
func (k *killLedger) reserveAt(addr string, severity admission.Severity, expires time.Time) admission.AttemptRecord {
	k.t.Helper()
	episode, err := admission.ParseEpisodeID("00000000000000000000000000000002")
	if err != nil {
		k.t.Fatal(err)
	}
	target, err := admission.CanonicalAddress(addr, admission.Caps{IPv6: true})
	if err != nil {
		k.t.Fatal(err)
	}
	evidence, err := k.producer.Mint(admission.EvidenceInput{
		Check: "ssh_brute", FindingID: "0123456789abcdef", Severity: severity,
		Observation: admission.ObservationRef{Stream: "fixture", Cursor: "evict=" + addr, Version: 1},
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
	return a
}

// runMember records a's batch as running and returns its member as the
// owner hands it to the engine, with the victim its intent names.
func (k *killLedger) runMember(a admission.AttemptRecord, addr string) firewall.BlockMember {
	k.t.Helper()
	intents, granted, err := k.l.ExecuteBatch([]admission.ActionID{a.Attempt.ID})
	if err != nil || !granted || len(intents) != 1 {
		k.t.Fatalf("recording %s as running = %v, %t, %v", addr, intents, granted, err)
	}
	m := firewall.BlockMember{Action: string(a.Attempt.ID), IP: addr, Reason: "CSM auto-block: ssh_brute", ExpiresAt: a.ExpiresAt}
	if v := intents[0].Victim; v != (admission.Victim{}) {
		ip, _ := v.Target.Addr()
		m.Victim = firewall.BlockVictim{Action: string(v.Action), IP: ip.String(), ExpiresAt: v.ExpiresAt}
	}
	return m
}

// Kill points around an eviction (spec 5.4, 5.5): a verified Warning
// block fills the general partition, and a Critical block of another
// address claims it and runs in a batch that deletes the victim and adds
// the block. The process stops at each step. Until the ledger records the
// verified eviction the victim's row stays, so a restart or reboot
// restores the victim and holds the block back as unknown, with the
// victim still counted. Once the eviction is recorded, a restart removes
// the victim's row and restores only the block, as retirement does at
// runtime.
func TestBlockEvictionConvergesAfterAKill(t *testing.T) {
	const victimIP, blockIP = "2001:db8::75", "203.0.113.76"
	for _, tc := range []struct {
		name string
		kill firewall.KillPoint
		// sent is whether the kernel took the batch; finish records the
		// verified eviction and retire then removes the victim's row.
		sent, finish, retire, unproven bool
	}{
		{"before the intent", firewall.KillBeforeIntent, false, false, false, false},
		{"before the kernel", firewall.KillBeforeKernel, false, false, false, false},
		{"before the readback", firewall.KillBeforeReadback, true, false, false, false},
		{"before the restore", firewall.KillBeforeRestore, false, false, false, false},
		{"before the outcome", "", true, false, false, false},
		{"before the retirement", "", true, true, false, false},
		{"after the retirement", "", true, true, true, false},
		{"before the unknown mark", firewall.KillBeforeMark, true, false, false, true},
		{"after the unknown mark", firewall.KillAfterMark, true, false, false, true},
		{"after the unknown outcome", "", true, false, false, true},
	} {
		for _, reboot := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reboot=%t", tc.name, reboot), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					at := time.Now().UTC().Round(0)
					dir := t.TempDir()
					stateDir := filepath.Join(dir, "firewall")
					if err := os.MkdirAll(stateDir, 0o700); err != nil {
						t.Fatal(err)
					}
					statePath := filepath.Join(stateDir, "state.json")
					if err := os.WriteFile(statePath, []byte(`{"blocked":[]}`), 0o600); err != nil {
						t.Fatal(err)
					}
					k := newKillLedger(t, dir, at)
					if err := k.l.StartLive(admission.LegacyHandover{}); err != nil {
						t.Fatal(err)
					}
					k.l.SetOccupants(&admission.SetOccupancy{Limit: 5, Unclaimed: 3})
					kernel := map[string]time.Duration{}

					low := k.reserveAt(victimIP, admission.SeverityWarning, at.Add(time.Hour))
					e, _ := k.engine(stateDir, at, kernel, map[string]time.Duration{victimIP: time.Hour}, "")
					if results, err := e.ApplyBlockBatch([]firewall.BlockMember{k.runMember(low, victimIP)}); err != nil || results[0].Effect != firewall.BlockApplied {
						t.Fatalf("victim batch = %+v, %v", results, err)
					}
					if _, _, err := k.l.Finish(low.Attempt.ID, admission.DispositionApplied); err != nil {
						t.Fatal(err)
					}
					high := k.reserveAt(blockIP, admission.SeverityCritical, at.Add(2*time.Hour))
					m := k.runMember(high, blockIP)
					if m.Victim.Action != string(low.Attempt.ID) || m.Victim.IP != victimIP {
						t.Fatalf("the block claimed %+v", m.Victim)
					}

					e, _ = k.engine(stateDir, at, kernel, map[string]time.Duration{blockIP: 2 * time.Hour}, tc.kill)
					if tc.unproven {
						firewall.UnreadEvictionVictimForTest(e, victimIP)
					}
					func() {
						if tc.kill != "" {
							defer func() {
								if got := recover(); got != tc.kill {
									t.Fatalf("kill point = %v, want %v", got, tc.kill)
								}
							}()
						}
						results, err := e.ApplyBlockBatch([]firewall.BlockMember{m})
						wantEffect, wantVictim := firewall.BlockApplied, firewall.VictimRemoved
						if tc.unproven {
							wantEffect, wantVictim = firewall.BlockUnknown, firewall.VictimUnproven
						}
						if err != nil || len(results) != 1 || results[0].Effect != wantEffect || results[0].Victim != wantVictim {
							t.Fatalf("eviction batch = %+v, %v", results, err)
						}
					}()
					wantKernel := map[string]time.Duration{victimIP: time.Hour}
					if tc.sent {
						wantKernel = map[string]time.Duration{blockIP: 2 * time.Hour}
					}
					if !maps.Equal(kernel, wantKernel) {
						t.Fatalf("after the stop the kernel holds %v; want %v", kernel, wantKernel)
					}
					if tc.finish {
						if _, _, err := k.l.FinishEviction(high.Attempt.ID, admission.DispositionApplied, admission.VictimRemoved, 0); err != nil {
							t.Fatal(err)
						}
					}
					if tc.unproven {
						rows := killRows(t, statePath)
						wantMark := tc.kill != firewall.KillBeforeMark
						if rows[victimIP].ActionID != m.Victim.Action || rows[victimIP].Unverified || rows[blockIP].ActionID != m.Action || rows[blockIP].Unverified != wantMark {
							t.Fatalf("unknown-removal rows %+v; member marked %t, victim verified", rows, wantMark)
						}
						if tc.kill == "" {
							if _, _, err := k.l.FinishEviction(high.Attempt.ID, admission.DispositionUnknown, admission.VictimUnproven, 0); err != nil {
								t.Fatal(err)
							}
						}
					}
					if tc.retire {
						if _, err := e.MarkBlockActionsUnverified([]string{m.Victim.Action}); err != nil {
							t.Fatal(err)
						}
						clear, err := e.RetireBlockActions([]firewall.BlockAction{{Action: m.Victim.Action, IP: victimIP}})
						if err != nil || len(clear) != 1 || !clear[0] {
							t.Fatalf("retiring the victim's row = %v, %v", clear, err)
						}
						if _, held := killRows(t, statePath)[victimIP]; held {
							t.Fatal("retirement kept the victim's row")
						}
					}
					if reboot {
						clear(kernel)
					}

					restart := at.Add(time.Minute)
					k.restart(restart, reboot)
					engine, seed := k.engine(stateDir, restart, kernel, nil, "")
					gate(t, k, restart, engine, statePath, seed)
					want, effects := map[string]time.Duration{victimIP: 59 * time.Minute}, admission.EffectTally{General: 2}
					if tc.finish {
						want, effects = map[string]time.Duration{blockIP: 119 * time.Minute}, admission.EffectTally{General: 1}
					}
					if !maps.Equal(kernel, want) {
						t.Fatalf("after the restart the kernel holds %v; want %v", kernel, want)
					}
					if tc.unproven {
						rows := killRows(t, statePath)
						if !rows[blockIP].Unverified || rows[victimIP].Unverified {
							t.Fatalf("startup marked the wrong row: %+v", rows)
						}
					}
					if _, held := killRows(t, statePath)[victimIP]; held == tc.finish {
						t.Fatalf("victim row held %t after the restart; want %t", held, !tc.finish)
					}
					if s := k.l.Status().Effects; s.General != effects.General || s.Reserved != effects.Reserved {
						t.Fatalf("the ledger counts %+v; want %+v", s, effects)
					}
					wantState := admission.StateUnknown
					if tc.finish {
						wantState = admission.StateVerified
					}
					if a := k.attempt(m.Action); a.State != wantState {
						t.Fatalf("the block after the restart = %+v; want %v", a, wantState)
					}
				})
			})
		}
	}
}
