//go:build linux

package firewall

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type expiryTestClock struct{ now time.Time }

func (c *expiryTestClock) Now() time.Time { return c.now }

func expiryScanCount(e *Engine) uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.expiryScans
}

// Lookups run once per candidate address in the netblock and auto-block
// passes, thousands of times per cycle on a host with thousands of blocks.
// Scanning every cached entry for expiry on each lookup made that pass
// quadratic. A lookup may scan only when some entry has actually come due.
func TestEngineLookupsSkipExpiryScanUntilEntryDue(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	clock := &expiryTestClock{now: base}
	e := &Engine{statePath: t.TempDir(), expiryClock: clock.Now}
	writeRawFirewallState(t, e, FirewallState{
		Blocked: []BlockedEntry{
			{IP: "192.0.2.10", BlockedAt: base},
			{IP: "192.0.2.11", BlockedAt: base, ExpiresAt: base.Add(10 * time.Minute)},
		},
		BlockedNet: []SubnetEntry{{CIDR: "198.51.100.0/24", BlockedAt: base, ExpiresAt: base.Add(30 * time.Minute)}},
		Allowed:    []AllowedEntry{{IP: "203.0.113.7", ExpiresAt: base.Add(20 * time.Minute)}},
	})
	lookups := func() {
		for i := 0; i < 1000; i++ {
			e.IsAllowed("203.0.113.7")
			e.IsBlocked("192.0.2.11")
			e.IsSubnetBlocked("198.51.100.0/24")
		}
	}
	wantScans := func(step string, want uint64) {
		t.Helper()
		if got := expiryScanCount(e); got != want {
			t.Fatalf("%s: expiry scans = %d, want %d", step, got, want)
		}
	}

	if !e.IsBlocked("192.0.2.11") {
		t.Fatal("unexpired block not reported")
	}
	wantScans("first lookup scans the loaded state", 1)
	lookups()
	wantScans("3000 lookups with nothing due", 1)

	clock.now = base.Add(10*time.Minute - time.Nanosecond)
	lookups()
	wantScans("one nanosecond before the first expiry", 1)
	if !e.IsBlocked("192.0.2.11") {
		t.Fatal("block dropped before it expired")
	}

	clock.now = base.Add(10 * time.Minute)
	if e.IsBlocked("192.0.2.11") {
		t.Fatal("block still reported at its expiry time")
	}
	wantScans("block came due", 2)
	lookups()
	wantScans("lookups after the due block was pruned", 2)
	if !e.IsAllowed("203.0.113.7") || !e.IsSubnetBlocked("198.51.100.0/24") || !e.IsBlocked("192.0.2.10") {
		t.Fatal("pruning one expired block dropped unexpired entries")
	}

	clock.now = base.Add(20 * time.Minute)
	if e.IsAllowed("203.0.113.7") {
		t.Fatal("allow still reported at its expiry time")
	}
	wantScans("allow came due", 3)

	clock.now = base.Add(30 * time.Minute)
	if e.IsSubnetBlocked("198.51.100.0/24") {
		t.Fatal("subnet block still reported at its expiry time")
	}
	wantScans("subnet came due", 4)

	clock.now = base.Add(1000 * time.Hour)
	lookups()
	wantScans("only permanent entries left", 4)
	if !e.IsBlocked("192.0.2.10") {
		t.Fatal("permanent block dropped")
	}
}

// Block churn decides how often entries come due, not how often lookups
// run. An attacker who staggers expiry times gets at most one scan per
// expiry moment crossed, never one per lookup.
func TestEngineExpiryScansFollowDueMomentsNotLookups(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	clock := &expiryTestClock{now: base}
	e := &Engine{statePath: t.TempDir(), expiryClock: clock.Now}
	const entries = 200
	state := FirewallState{}
	for i := 1; i <= entries; i++ {
		state.Blocked = append(state.Blocked, BlockedEntry{
			IP:        fmt.Sprintf("192.0.2.%d", i),
			BlockedAt: base,
			ExpiresAt: base.Add(time.Duration(i) * time.Second),
		})
	}
	writeRawFirewallState(t, e, state)
	if !e.IsBlocked("192.0.2.1") {
		t.Fatal("unexpired block not reported")
	}
	lookups := 1
	for i := 1; i <= entries; i++ {
		clock.now = base.Add(time.Duration(i) * time.Second)
		for j := 0; j < 50; j++ {
			e.IsAllowed("203.0.113.7")
			lookups++
		}
		lookups++
		if e.IsBlocked(fmt.Sprintf("192.0.2.%d", i)) {
			t.Fatalf("entry %d still blocked at its expiry time", i)
		}
		if i < entries {
			lookups++
			if !e.IsBlocked(fmt.Sprintf("192.0.2.%d", i+1)) {
				t.Fatalf("entry %d dropped before its expiry time", i+1)
			}
		}
	}
	if got, want := expiryScanCount(e), uint64(1+entries); got != want {
		t.Fatalf("expiry scans = %d over %d lookups, want %d (initial scan plus one per expiry moment)", got, lookups, want)
	}
}

// Saving state installs a new cache. A deadline computed for the previous
// cache must not hide an entry that expires sooner, and must not drop an
// entry whose expiry was extended.
func TestEngineSavedStateExpiryIsHonored(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	clock := &expiryTestClock{now: base}
	e := &Engine{statePath: t.TempDir(), expiryClock: clock.Now}
	writeRawFirewallState(t, e, FirewallState{
		Blocked: []BlockedEntry{
			{IP: "192.0.2.20", BlockedAt: base, ExpiresAt: base.Add(time.Hour)},
			{IP: "192.0.2.21", BlockedAt: base, ExpiresAt: base.Add(5 * time.Minute)},
		},
	})
	if !e.IsBlocked("192.0.2.20") {
		t.Fatal("unexpired block not reported")
	}

	e.mu.Lock()
	next := e.loadStateFile()
	next.Blocked[0].ExpiresAt = base.Add(5 * time.Minute) // shortened
	next.Blocked[1].ExpiresAt = base.Add(2 * time.Hour)   // extended
	next.Blocked = append(next.Blocked, BlockedEntry{IP: "192.0.2.22", BlockedAt: base, ExpiresAt: base.Add(time.Minute)})
	if err := e.saveState(&next); err != nil {
		e.mu.Unlock()
		t.Fatalf("saveState: %v", err)
	}
	e.mu.Unlock()

	clock.now = base.Add(time.Minute)
	if e.IsBlocked("192.0.2.22") {
		t.Fatal("newly saved block outlived its expiry")
	}
	clock.now = base.Add(5 * time.Minute)
	if e.IsBlocked("192.0.2.20") {
		t.Fatal("shortened block outlived its new expiry")
	}
	if !e.IsBlocked("192.0.2.21") {
		t.Fatal("extended block dropped at its old expiry")
	}
	clock.now = base.Add(2 * time.Hour)
	if e.IsBlocked("192.0.2.21") {
		t.Fatal("extended block outlived its new expiry")
	}
}

// A state.json rewritten by another writer is reloaded. Its own expiry
// times apply, not the deadline of the state it replaced.
func TestEngineReloadedStateExpiryIsHonored(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	clock := &expiryTestClock{now: base}
	e := &Engine{statePath: t.TempDir(), expiryClock: clock.Now}
	writeRawFirewallState(t, e, FirewallState{
		Blocked: []BlockedEntry{{IP: "192.0.2.30", BlockedAt: base, ExpiresAt: base.Add(time.Hour)}},
	})
	if !e.IsBlocked("192.0.2.30") {
		t.Fatal("unexpired block not reported")
	}
	writeRawFirewallState(t, e, FirewallState{
		Blocked: []BlockedEntry{
			{IP: "192.0.2.30", BlockedAt: base, ExpiresAt: base.Add(time.Hour)},
			{IP: "192.0.2.31", BlockedAt: base, ExpiresAt: base.Add(time.Minute)},
		},
	})
	if !e.IsBlocked("192.0.2.31") {
		t.Fatal("reloaded block not reported")
	}
	clock.now = base.Add(time.Minute)
	if e.IsBlocked("192.0.2.31") {
		t.Fatal("reloaded block outlived its expiry")
	}
	if !e.IsBlocked("192.0.2.30") {
		t.Fatal("unexpired block dropped")
	}
}

// A kept prior cache (unreadable rewrite) still expires on schedule.
func TestEngineKeptPriorCacheStillExpires(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	clock := &expiryTestClock{now: base}
	e := &Engine{statePath: t.TempDir(), expiryClock: clock.Now}
	writeRawFirewallState(t, e, FirewallState{
		Blocked: []BlockedEntry{{IP: "192.0.2.40", BlockedAt: base, ExpiresAt: base.Add(time.Minute)}},
	})
	if !e.IsBlocked("192.0.2.40") {
		t.Fatal("unexpired block not reported")
	}
	if err := os.WriteFile(filepath.Join(e.statePath, "state.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !e.IsBlocked("192.0.2.40") {
		t.Fatal("prior cache not kept across an invalid rewrite")
	}
	clock.now = base.Add(time.Minute)
	if e.IsBlocked("192.0.2.40") {
		t.Fatal("kept prior cache outlived its expiry")
	}
}

type committedStateOnlyStore struct {
	ActionStore
	current *FirewallState
}

func (s committedStateOnlyStore) ReadFirewallState() (FirewallState, uint64, error) {
	return copyFirewallState(*s.current), 1, nil
}

// Installing committed lifecycle state replaces the cache, so its expiry
// times apply even when an earlier snapshot expired later.
func TestEngineCommittedStateExpiryIsHonored(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	clock := &expiryTestClock{now: base}
	current := FirewallState{
		Blocked: []BlockedEntry{{IP: "192.0.2.50", BlockedAt: base, ExpiresAt: base.Add(time.Hour)}},
	}
	e := &Engine{
		expiryClock: clock.Now,
		lifecycle:   &Lifecycle{Store: committedStateOnlyStore{current: &current}},
	}
	if !e.IsBlocked("192.0.2.50") {
		t.Fatal("unexpired committed block not reported")
	}
	current.Blocked = append(current.Blocked, BlockedEntry{IP: "192.0.2.51", BlockedAt: base, ExpiresAt: base.Add(time.Minute)})
	if !e.IsBlocked("192.0.2.51") {
		t.Fatal("newly committed block not reported")
	}
	clock.now = base.Add(time.Minute)
	if e.IsBlocked("192.0.2.51") {
		t.Fatal("committed block outlived its expiry")
	}
	if !e.IsBlocked("192.0.2.50") {
		t.Fatal("unexpired committed block dropped")
	}
}

// The skip must never outlast what the prune itself would drop, whether a
// cached expiry carries a monotonic reading (made in this process) or not
// (decoded from disk), and whether the clock does.
func TestExpiryDeadlineReachedWheneverPruneWouldDrop(t *testing.T) {
	t0 := time.Now()
	var state FirewallState
	for i := 1; i <= 40; i++ {
		at := t0.Add(time.Duration(i) * time.Millisecond)
		if i%2 == 0 {
			at = at.Round(0)
		}
		switch i % 3 {
		case 0:
			state.Blocked = append(state.Blocked, BlockedEntry{IP: fmt.Sprintf("192.0.2.%d", i), ExpiresAt: at})
		case 1:
			state.BlockedNet = append(state.BlockedNet, SubnetEntry{CIDR: fmt.Sprintf("198.51.100.%d/32", i), ExpiresAt: at})
		default:
			state.Allowed = append(state.Allowed, AllowedEntry{IP: fmt.Sprintf("203.0.113.%d", i), ExpiresAt: at})
		}
	}
	for _, start := range []time.Time{t0, t0.Round(0)} {
		d := nextExpiryDeadline(&state, start)
		for j := 0; j <= 41; j++ {
			for _, now := range []time.Time{t0.Add(time.Duration(j) * time.Millisecond), t0.Add(time.Duration(j) * time.Millisecond).Round(0)} {
				_, dropBlocked := pruneBlocked(state.Blocked, now)
				_, dropNet := pruneBlockedNet(state.BlockedNet, now)
				_, dropAllowed := pruneAllowed(state.Allowed, now)
				due := dropBlocked || dropNet || dropAllowed
				if got := d.reached(&state, now); got != due {
					t.Fatalf("start mono=%v now=+%dms mono=%v: reached=%v, prune drops=%v", start != start.Round(0), j, now != now.Round(0), got, due)
				}
			}
		}
	}
	other := copyFirewallState(state)
	if d := nextExpiryDeadline(&state, t0); !d.reached(&other, t0) {
		t.Fatal("deadline computed for one snapshot applied to another")
	}
	if d := nextExpiryDeadline(&FirewallState{Blocked: []BlockedEntry{{IP: "192.0.2.1"}}}, t0); d.reached(d.state, t0.Add(1000*time.Hour)) {
		t.Fatal("permanent entries reported as due")
	}
}

func BenchmarkEngineIsAllowedWithManyTimedBlocks(b *testing.B) {
	dir := b.TempDir()
	e := &Engine{statePath: dir}
	now := time.Now()
	var state FirewallState
	for i := 0; i < 3500; i++ {
		state.Blocked = append(state.Blocked, BlockedEntry{
			IP:        fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff),
			BlockedAt: now,
			ExpiresAt: now.Add(24*time.Hour + time.Duration(i)*time.Second),
		})
	}
	data, err := json.Marshal(state)
	if err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0o600); err != nil {
		b.Fatal(err)
	}
	e.IsAllowed("203.0.113.7")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.IsAllowed("203.0.113.7")
	}
}
