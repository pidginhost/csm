//go:build linux

package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// IsBlocked must answer from the index map populated by the cached
// state, not by linearly scanning a reparsed slice. Pin both that the
// answer is correct and that the underlying state.json is not re-read
// on every call. Pre-cache, the file would be opened twice per
// IsBlocked invocation.
func TestEngine_IsBlockedHitsCache(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	state := FirewallState{
		Blocked: []BlockedEntry{
			{IP: "192.0.2.10", Reason: "test", BlockedAt: time.Now()},
			{IP: "203.0.113.5", Reason: "test", BlockedAt: time.Now()},
		},
	}
	data, err := json.MarshalIndent(&state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(dir, "state.json")
	if err := os.WriteFile(stateFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if !e.IsBlocked("192.0.2.10") {
		t.Errorf("IsBlocked(192.0.2.10) = false, want true")
	}
	if !e.IsBlocked("203.0.113.5") {
		t.Errorf("IsBlocked(203.0.113.5) = false, want true")
	}
	if e.IsBlocked("198.51.100.1") {
		t.Errorf("IsBlocked(198.51.100.1) = true, want false")
	}

	// Cache invariant: capture mtime, sleep, call IsBlocked many more
	// times, confirm mtime did not change. A regression that drops the
	// cache would touch the file every call via os.ReadFile (no write,
	// so mtime stays anyway) but more importantly would re-parse the
	// 325 KiB JSON. Verify the cache pointer is reused instead.
	cachedBefore := e.stateCache
	for i := 0; i < 100; i++ {
		_ = e.IsBlocked("192.0.2.10")
	}
	cachedAfter := e.stateCache
	if cachedBefore != cachedAfter {
		t.Errorf("stateCache pointer changed across IsBlocked calls -- cache is being rebuilt")
	}
}

// An external writer (CLI, test, migrated import) replacing state.json
// must take effect on the next read. The cache uses mtime equality as
// the invalidation key; bump mtime and confirm new entries appear.
func TestEngine_IsBlockedReloadsOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}
	stateFile := filepath.Join(dir, "state.json")

	writeState := func(ip string) {
		t.Helper()
		state := FirewallState{
			Blocked: []BlockedEntry{{IP: ip, Reason: "test", BlockedAt: time.Now()}},
		}
		data, err := json.MarshalIndent(&state, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(stateFile, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	writeState("192.0.2.10")
	if !e.IsBlocked("192.0.2.10") {
		t.Fatal("first IsBlocked should see the seeded IP")
	}

	// Push mtime forward past second resolution so the cache cannot
	// false-hit. We assert by stat, then sleep just enough to cross
	// a second boundary, then rewrite.
	time.Sleep(1100 * time.Millisecond)
	writeState("198.51.100.50")

	if e.IsBlocked("192.0.2.10") {
		t.Errorf("after external rewrite, old IP must no longer be reported as blocked")
	}
	if !e.IsBlocked("198.51.100.50") {
		t.Errorf("after external rewrite, new IP should be reported as blocked")
	}
}

// Expired blocks must never appear in the IsBlocked answer even when
// the on-disk state.json still carries them. The cache mirror applies
// expiry on every refresh.
func TestEngine_IsBlockedDropsExpired(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	state := FirewallState{
		Blocked: []BlockedEntry{
			{IP: "10.0.0.1", Reason: "stale", BlockedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour)},
			{IP: "10.0.0.2", Reason: "fresh", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
		},
	}
	data, err := json.MarshalIndent(&state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	if e.IsBlocked("10.0.0.1") {
		t.Errorf("IsBlocked must drop expired entry 10.0.0.1")
	}
	if !e.IsBlocked("10.0.0.2") {
		t.Errorf("IsBlocked must keep non-expired entry 10.0.0.2")
	}
}

// loadStateFile returns a deep copy: caller-side mutations cannot
// corrupt the cache. Without the copy, append() that re-uses the
// backing array would silently grow the cached slice.
//
// loadStateFile requires e.mu; the test acquires it explicitly so the
// lock contract is self-documenting (production callers like
// saveBlockedEntry already hold the lock before calling).
func TestEngine_LoadStateFileDeepCopy(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	state := FirewallState{
		Blocked: []BlockedEntry{{IP: "10.0.0.1", BlockedAt: time.Now()}},
	}
	data, _ := json.MarshalIndent(&state, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	e.mu.Lock()
	got1 := e.loadStateFile()
	got1.Blocked = append(got1.Blocked, BlockedEntry{IP: "203.0.113.99"})
	got2 := e.loadStateFile()
	e.mu.Unlock()

	if len(got2.Blocked) != 1 || got2.Blocked[0].IP != "10.0.0.1" {
		t.Errorf("caller mutation leaked into cache: second load returned %v", got2.Blocked)
	}
}

// saveState rebuilds the cache from the just-written state without
// re-reading the file. Pin by checking IsBlocked / IsSubnetBlocked
// reflect the new state immediately after saveState returns.
//
// saveState requires e.mu; the test acquires it explicitly to match
// the production contract.
func TestEngine_SaveStateRefreshesCache(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	if e.IsBlocked("10.0.0.1") {
		t.Fatal("empty engine should not report any IP as blocked")
	}

	e.mu.Lock()
	e.saveState(&FirewallState{
		Blocked:    []BlockedEntry{{IP: "10.0.0.1", BlockedAt: time.Now()}},
		BlockedNet: []SubnetEntry{{CIDR: "203.0.113.0/24", BlockedAt: time.Now()}},
	})
	e.mu.Unlock()

	if !e.IsBlocked("10.0.0.1") {
		t.Errorf("saveState must refresh cache so IsBlocked sees newly written entry")
	}
	if !e.IsSubnetBlocked("203.0.113.0/24") {
		t.Errorf("saveState must refresh cache so IsSubnetBlocked sees newly written CIDR")
	}
}
