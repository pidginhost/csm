//go:build linux

package firewall

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
)

func TestDurableEvictionUsesCompleteCommittedState(t *testing.T) {
	for _, expiredAlias := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired unrelated rows", true: "expired alias"}[expiredAlias], func(t *testing.T) {
			now := time.Now().Round(0)
			soon := BlockedEntry{IP: "203.0.113.51", Reason: "soon", BlockedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
			later := BlockedEntry{IP: "203.0.113.52", Reason: "later", BlockedAt: now.Add(-time.Hour), ExpiresAt: now.Add(2 * time.Hour)}
			expired := soon
			expired.IP, expired.ExpiresAt = "192.0.2.81", now.Add(-time.Minute)
			victim, kept := soon, []BlockedEntry{expired, later}
			if expiredAlias {
				expired.IP = "::ffff:203.0.113.51"
				victim, kept = later, []BlockedEntry{soon, expired}
			}
			state := FirewallState{Blocked: []BlockedEntry{soon, expired, later}, Allowed: []AllowedEntry{{IP: "192.0.2.80", ExpiresAt: now.Add(-time.Hour)}}}
			e, s := batchPlanEngine(t, FirewallConfig{DenyTempIPLimit: 2}, state)
			// The allow set is empty even though the block set has live rows.
			blocked, empty := e.conn.TestDial, leaseActionReadConn(t, nil).TestDial
			e.conn.TestDial = func(req []netlink.Message) ([]netlink.Message, error) {
				if len(req) > 0 && strings.Contains(string(req[0].Data), "allowed_ips") {
					return empty(req)
				}
				return blocked(req)
			}
			req := batchMember("evicting", "203.0.113.53")
			if _, err := e.BlockIPRequest(req, nil); !errors.Is(err, errBatchPlanStop) || len(s.admitted) != 1 {
				t.Fatalf("plan = %v, %d admissions", err, len(s.admitted))
			}
			a := s.admitted[0]
			if len(a.Members) != 1 || !reflect.DeepEqual(a.Members[0].Victims, []BlockedEntry{victim}) {
				t.Fatalf("wrong victim selected: %#v", a.Members)
			}
			if !reflect.DeepEqual(a.Before, state) || len(a.After.Blocked) != 3 || !SameBlockedEntry(a.After.Blocked[0], kept[0]) || !SameBlockedEntry(a.After.Blocked[1], kept[1]) || !reflect.DeepEqual(a.After.Allowed, state.Allowed) {
				t.Fatalf("cache pruning leaked into plan: %#v", a)
			}
		})
	}
}

func TestDurableEvictionKeepsExpiredRowsOutOfPolicy(t *testing.T) {
	for _, mode := range []string{"expired owned target", "fallback capacity"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().Round(0)
			expired := BlockedEntry{IP: "203.0.113.50", ActionID: "older-member", BlockedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}
			state := FirewallState{Blocked: []BlockedEntry{expired}}
			target := expired.IP
			cfg := FirewallConfig{}
			if mode == "fallback capacity" {
				target = "203.0.113.52"
				cfg.DenyTempIPLimit = 2
				state.Blocked = append(state.Blocked, BlockedEntry{IP: "203.0.113.51", ExpiresAt: now.Add(time.Hour)})
			}
			e, store := batchPlanEngine(t, cfg, state)
			e.liveBlockCounts = func() (int, int, error) { return 0, 0, errors.New("counts unavailable") }
			if _, err := e.BlockIPRequest(batchMember("fresh", target), nil); !errors.Is(err, errBatchPlanStop) || len(store.admitted) != 1 {
				t.Fatalf("expired row suppressed fresh block: %v, %d admissions", err, len(store.admitted))
			}
			action := store.admitted[0]
			if len(action.Members) != 0 {
				t.Fatalf("expired row inflated capacity and caused eviction: %#v", action.Members)
			}
			if !reflect.DeepEqual(action.Before, state) {
				t.Fatal("policy filtering changed the saved before state")
			}
			if mode == "fallback capacity" && (len(action.After.Blocked) != 3 || !SameBlockedEntry(action.After.Blocked[0], expired) || !SameBlockedEntry(action.After.Blocked[1], state.Blocked[1])) {
				t.Fatalf("capacity planning changed unrelated rows: %#v", action.After.Blocked)
			}
		})
	}
}

func TestDurableEvictionCandidatesAreUniqueAndTimed(t *testing.T) {
	now := time.Now().Round(0)
	row := BlockedEntry{IP: "203.0.113.50", ExpiresAt: now.Add(time.Hour)}
	for name, other := range map[string]BlockedEntry{
		"expired alias":   {IP: "::ffff:203.0.113.50", ExpiresAt: now.Add(-time.Hour)},
		"permanent alias": {IP: "::ffff:203.0.113.50"},
		"owned alias":     {IP: "::ffff:203.0.113.50", ActionID: "older", ExpiresAt: now.Add(time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			e, _ := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
			if ip, ok := e.evictionVictimLocked(FirewallState{Blocked: []BlockedEntry{row, other}}, "203.0.113.60", true); ok {
				t.Fatalf("ambiguous victim %s", ip)
			}
		})
	}
	e, _ := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
	for _, r := range []BlockedEntry{{IP: row.IP}, {IP: row.IP, ExpiresAt: now.Add(-time.Hour)}, {IP: row.IP, ExpiresAt: now.Add(time.Hour), Unverified: true}} {
		if ip, ok := e.evictionVictimLocked(FirewallState{Blocked: []BlockedEntry{r}}, "203.0.113.60", true); ok {
			t.Fatalf("ineligible victim %s: %#v", ip, r)
		}
	}
}

func TestFirewallAuditDoesNotEvictStorageOnlyVictims(t *testing.T) {
	sink := captureFirewallAudit(t)
	at := time.Now().Round(0)
	v := BlockedEntry{IP: "203.0.113.90", ExpiresAt: at.Add(-time.Hour)}
	a := FirewallAction{Request: batchHeader(), Members: []ActionMember{{Request: batchMember("a", "203.0.113.10"), Victims: []BlockedEntry{v}}, {Request: batchMember("b", "203.0.113.11")}}, Before: FirewallState{Blocked: []BlockedEntry{v}}, Phase: "verified"}
	if err := writeFirewallActionAudit(a); err != nil {
		t.Fatal(err)
	}
	if len(sink.batch) != 1 || len(sink.batch[0]) != 2 {
		t.Fatalf("batch expiry audited as eviction: %#v", sink.batch)
	}
	for _, record := range sink.batch[0] {
		if record.Action != "block" {
			t.Fatalf("storage-only victim audited: %#v", record)
		}
	}
	// The manifest alone cannot prove that a one-member action held a victim.
	a.Members = a.Members[:1]
	a.Request = a.Members[0].Request
	for _, before := range []FirewallState{{}, {Blocked: []BlockedEntry{{IP: v.IP, ExpiresAt: v.ExpiresAt, Reason: "different"}}}} {
		a.Before = before
		sink.single, sink.batch = nil, nil
		if err := writeFirewallActionAudit(a); err != nil {
			t.Fatal(err)
		}
		if len(sink.single) != 1 || len(sink.batch) != 0 {
			t.Fatalf("unheld victim audited: %#v %#v", sink.single, sink.batch)
		}
	}
}

// In-memory safety marks affect eligibility, never the saved row identity.
func TestDurableEvictionHonorsPolicyOverlay(t *testing.T) {
	for _, mark := range []string{"unverified", "failed"} {
		t.Run(mark, func(t *testing.T) {
			now := time.Now().Round(0)
			held := BlockedEntry{IP: "203.0.113.50", ActionID: "unsettled", ExpiresAt: now.Add(time.Hour)}
			eligible := BlockedEntry{IP: "203.0.113.51", ExpiresAt: now.Add(2 * time.Hour)}
			state := FirewallState{Blocked: []BlockedEntry{held, eligible}}
			e, store := batchPlanEngine(t, FirewallConfig{DenyTempIPLimit: 2}, state)
			if mark == "unverified" {
				e.unverifiedBlockActions = map[string]bool{held.ActionID: true}
			} else {
				e.failedBlockActions = map[string]bool{held.ActionID: true}
			}
			e.liveBlockCounts = func() (int, int, error) { return 0, 2, nil }
			req := ActionRequest{ID: "operator", Target: "203.0.113.52", Actor: "cli", Source: "cli", TTL: time.Hour}
			if _, err := e.BlockIPRequest(req, nil); !errors.Is(err, errBatchPlanStop) || len(store.admitted) != 1 {
				t.Fatalf("forced block = %v, %d admissions", err, len(store.admitted))
			}
			plan := store.admitted[0]
			if len(plan.Members) != 1 || !reflect.DeepEqual(plan.Members[0].Victims, []BlockedEntry{eligible}) {
				t.Fatalf("policy-marked row selected as victim: %#v", plan.Members)
			}
			if !reflect.DeepEqual(plan.Before, state) || len(plan.After.Blocked) != 2 || !SameBlockedEntry(plan.After.Blocked[0], held) {
				t.Fatalf("policy overlay changed saved state: %#v", plan)
			}
		})
	}
}

type victimReadStore struct {
	*batchPlanStore
	reads int
	fail  bool
	cause error
}

func (s *victimReadStore) ReadFirewallState() (FirewallState, uint64, error) {
	s.reads++
	if s.fail || s.reads > 1 {
		return FirewallState{}, 0, s.cause
	}
	return s.batchPlanStore.ReadFirewallState()
}

func TestDurableEvictionPlanningReadContract(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success clears prior error", true: "failure stays visible"}[fail], func(t *testing.T) {
			now := time.Now().Round(0)
			held := BlockedEntry{IP: "203.0.113.50", ActionID: "unsettled", ExpiresAt: now.Add(time.Hour)}
			state := FirewallState{Blocked: []BlockedEntry{held, {IP: "203.0.113.51", ExpiresAt: now.Add(-time.Hour)}}}
			e, base := batchPlanEngine(t, FirewallConfig{DenyTempIPLimit: 1}, state)
			wantState := copyFirewallState(state)
			cause := errors.New("snapshot unavailable")
			store := &victimReadStore{batchPlanStore: base, fail: fail, cause: cause}
			e.lifecycle.Store, e.stateReadErr = store, errors.New("earlier snapshot error")
			e.liveBlockCounts = func() (int, int, error) { return 0, 0, errors.New("counts unavailable") }
			e.unverifiedBlockActions = map[string]bool{held.ActionID: true}
			e.mu.Lock()
			_, _, _, _, err := e.blockIPTarget("203.0.113.52", time.Hour, true)
			e.mu.Unlock()
			if store.reads != 1 || fail && (!errors.Is(err, cause) || !errors.Is(e.stateReadErr, cause)) || !fail && (err != nil || e.stateReadErr != nil) {
				t.Fatalf("planning read: calls %d, error %v, saved error %v", store.reads, err, e.stateReadErr)
			}
			if !reflect.DeepEqual(base.state, wantState) {
				t.Fatal("policy projection changed the store snapshot")
			}
			if !fail && (len(e.stateCache.Blocked) != 1 || !e.stateCache.Blocked[0].Unverified) {
				t.Fatalf("planning lost its policy overlay: %#v", e.stateCache.Blocked)
			}
		})
	}
}

func TestDurableEvictionLeavesLegacyReadContract(t *testing.T) {
	e := newBlockedSetWireTestEngine(t, leaseActionReadConn(t, nil))
	e.stateReadErr = errors.New("old durable read")
	e.mu.Lock()
	_, _, _, _, err := e.blockIPTarget("203.0.113.52", time.Hour, true)
	e.mu.Unlock()
	if err != nil {
		t.Fatalf("legacy planning inherited durable read error: %v", err)
	}
}
