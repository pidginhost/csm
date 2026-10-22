package firewall

import (
	"reflect"
	"testing"
	"time"
)

// retireFixture is an unknown two-member batch planned two hours before now
// whose one-hour members have both expired.
func retireFixture(now time.Time) FirewallAction {
	planned := now.Add(-2 * time.Hour)
	permanent := BlockedEntry{IP: "192.0.2.1", Reason: "permanent", BlockedAt: planned.Add(-time.Hour)}
	allow := AllowedEntry{IP: "198.51.100.7", Reason: "operator"}
	a := manifestBatch()
	a.Members[0].Victims = nil
	a.Phase, a.CreatedAt = "unknown", planned
	a.Before = FirewallState{Blocked: []BlockedEntry{permanent}, Allowed: []AllowedEntry{allow}}
	a.After = FirewallState{Blocked: []BlockedEntry{permanent}, Allowed: []AllowedEntry{allow}}
	for _, m := range a.Members {
		a.After.Blocked = append(a.After.Blocked, BlockedEntry{IP: m.Request.Target, Reason: m.Request.Reason, Source: "scan", BlockedAt: planned, ExpiresAt: planned.Add(m.Request.TTL), ActionID: m.Request.ID})
	}
	return a
}

// An unknown block whose every effect has expired retires to the rows its
// Before and After states agree on.
func TestRetiredActionStateKeepsRowsBothStatesAgreeOn(t *testing.T) {
	now := time.Date(2026, 1, 2, 6, 0, 0, 0, time.UTC)
	a := retireFixture(now)
	if state, ok := RetiredActionState(a, now); !ok || !reflect.DeepEqual(state, a.Before) {
		t.Fatalf("batch retires to %#v, %v", state, ok)
	}
	// A single-target block that evicted: its own row and its victim have
	// both expired, so neither stays.
	planned := now.Add(-2 * time.Hour)
	victim := BlockedEntry{IP: "203.0.113.90", Reason: "earlier", Source: "scan", BlockedAt: planned.Add(-time.Hour), ExpiresAt: planned.Add(30 * time.Minute)}
	req := ActionRequest{ID: "evicting", Operation: "block", Target: "203.0.113.10", Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour}
	single := FirewallAction{
		Request: req, Members: []ActionMember{{Request: req, Victims: []BlockedEntry{victim}}}, Phase: "unknown", CreatedAt: planned,
		Before: FirewallState{Blocked: []BlockedEntry{a.Before.Blocked[0], victim}},
		After:  FirewallState{Blocked: []BlockedEntry{a.Before.Blocked[0], {IP: req.Target, Reason: req.Reason, BlockedAt: planned, ExpiresAt: planned.Add(time.Hour)}}},
	}
	if state, ok := RetiredActionState(single, now); !ok || !reflect.DeepEqual(state.Blocked, a.Before.Blocked) {
		t.Fatalf("single block retires to %#v, %v", state.Blocked, ok)
	}
	// An empty list and none are the same list.
	a.Before.Allowed, a.After.Allowed = nil, []AllowedEntry{}
	a.After.BlockedNet = []SubnetEntry{}
	a.After.PortAllowed = []PortAllowEntry{}
	if _, ok := RetiredActionState(a, now); !ok {
		t.Fatal("an empty port allow list counted as a change")
	}
	// Rows compare by value, whatever location their times carry.
	a = retireFixture(now)
	a.After.Blocked[0].BlockedAt = a.After.Blocked[0].BlockedAt.In(time.FixedZone("east", 2*60*60))
	if state, ok := RetiredActionState(a, now); !ok || len(state.Blocked) != 1 {
		t.Fatalf("a kept row in another location retires to %#v, %v", state.Blocked, ok)
	}
	// An effect that ends exactly now can no longer be live.
	a = retireFixture(now)
	a.After.Blocked[1].ExpiresAt = now
	if _, ok := RetiredActionState(a, now); !ok {
		t.Fatal("an effect ending now still holds the action")
	}
}

// Anything that could still be live, or that no expiry ends, keeps the
// action for an operator's Resolve.
func TestRetiredActionStateNeedsEveryEffectExpired(t *testing.T) {
	now := time.Date(2026, 1, 2, 6, 0, 0, 0, time.UTC)
	for name, change := range map[string]func(*FirewallAction){
		"member still live": func(a *FirewallAction) { a.After.Blocked[1].ExpiresAt = now.Add(time.Minute) },
		"permanent effect":  func(a *FirewallAction) { a.After.Blocked[1].ExpiresAt = time.Time{} },
		"unverified effect": func(a *FirewallAction) { a.After.Blocked[1].Unverified = true },
		"removed row still live": func(a *FirewallAction) {
			a.Before.Blocked = append(a.Before.Blocked, BlockedEntry{IP: "203.0.113.91", Reason: "earlier", BlockedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)})
		},
		"removed unverified expired row": func(a *FirewallAction) {
			a.Before.Blocked = append(a.Before.Blocked, BlockedEntry{IP: "203.0.113.93", Unverified: true, ExpiresAt: now.Add(-time.Hour)})
		},
		"removed permanent row": func(a *FirewallAction) {
			a.Before.Blocked = append(a.Before.Blocked, BlockedEntry{IP: "203.0.113.91", Reason: "earlier", BlockedAt: now.Add(-time.Hour)})
		},
		"unrelated addition still live": func(a *FirewallAction) {
			a.After.Blocked = append(a.After.Blocked, BlockedEntry{IP: "203.0.113.92", ExpiresAt: now.Add(time.Hour)})
		},
		"allow changed": func(a *FirewallAction) { a.After.Allowed = nil },
		"subnet changed": func(a *FirewallAction) {
			a.After.BlockedNet = []SubnetEntry{{CIDR: "198.51.100.0/28", Reason: "subnet", ExpiresAt: now.Add(-time.Hour)}}
		},
		"port allow changed": func(a *FirewallAction) {
			a.After.PortAllowed = []PortAllowEntry{{IP: "198.51.100.8", Port: 22, Proto: "tcp", Reason: "operator"}}
		},
		"not a block": func(a *FirewallAction) { a.Request.Operation = "unblock" },
	} {
		a := retireFixture(now)
		change(&a)
		if state, ok := RetiredActionState(a, now); ok {
			t.Errorf("%s: retired to %#v", name, state)
		}
	}
}
