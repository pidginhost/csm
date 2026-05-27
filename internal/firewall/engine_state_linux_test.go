//go:build linux

package firewall

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/nftables"
)

// These tests run only on Linux where engine.go compiles.
// They test the state file management (JSON I/O) without needing nftables.

func TestEngineLoadStateFileEmpty(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}
	state := e.loadStateFile()
	if len(state.Blocked) != 0 {
		t.Errorf("empty dir should return empty state, got %d blocked", len(state.Blocked))
	}
}

func TestEngineLoadStateFileWithData(t *testing.T) {
	dir := t.TempDir()
	state := FirewallState{
		Blocked: []BlockedEntry{
			{IP: "203.0.113.5", Reason: "brute-force", BlockedAt: time.Now()},
			{IP: "198.51.100.1", Reason: "waf", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(2 * time.Hour)},
		},
		Allowed: []AllowedEntry{
			{IP: "10.0.0.1", Reason: "admin"},
		},
	}
	data, _ := json.MarshalIndent(state, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "state.json"), data, 0600)

	e := &Engine{statePath: dir}
	loaded := e.loadStateFile()
	if len(loaded.Blocked) != 2 {
		t.Errorf("got %d blocked, want 2", len(loaded.Blocked))
	}
	if len(loaded.Allowed) != 1 {
		t.Errorf("got %d allowed, want 1", len(loaded.Allowed))
	}
}

func TestEngineLoadStateFileExpiryCleanup(t *testing.T) {
	dir := t.TempDir()
	state := FirewallState{
		Blocked: []BlockedEntry{
			{IP: "203.0.113.5", Reason: "active", BlockedAt: time.Now()},
			{IP: "198.51.100.1", Reason: "expired", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(-1 * time.Hour)},
		},
	}
	data, _ := json.MarshalIndent(state, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "state.json"), data, 0600)

	e := &Engine{statePath: dir}
	loaded := e.loadStateFile()
	if len(loaded.Blocked) != 1 {
		t.Errorf("expired entry should be cleaned: got %d, want 1", len(loaded.Blocked))
	}
}

func TestEngineSaveState(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}
	state := &FirewallState{
		Blocked: []BlockedEntry{{IP: "1.2.3.4", Reason: "test"}},
	}
	e.saveState(state)

	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("state.json not written: %v", err)
	}
	if len(data) == 0 {
		t.Error("state.json should not be empty")
	}
}

func TestEngineSaveBlockedEntry(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.5", Reason: "test"})

	state := e.loadStateFile()
	if len(state.Blocked) != 1 {
		t.Errorf("got %d blocked, want 1", len(state.Blocked))
	}
}

func TestEngineSaveBlockedEntryDedup(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.5", Reason: "first"})
	e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.5", Reason: "second"})

	state := e.loadStateFile()
	if len(state.Blocked) != 1 {
		t.Errorf("dedup should keep 1, got %d", len(state.Blocked))
	}
	if state.Blocked[0].Reason != "second" {
		t.Errorf("should update reason, got %q", state.Blocked[0].Reason)
	}
}

func TestEngineRemoveBlockedState(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.5", Reason: "test"})
	e.removeBlockedState("203.0.113.5")

	state := e.loadStateFile()
	if len(state.Blocked) != 0 {
		t.Errorf("removed IP should be gone, got %d", len(state.Blocked))
	}
}

func TestEngineSaveAllowedEntry(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "admin"})

	state := e.loadStateFile()
	if len(state.Allowed) != 1 {
		t.Errorf("got %d allowed, want 1", len(state.Allowed))
	}
}

func TestEngineRemoveAllowedState(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "admin"})
	e.removeAllowedState("10.0.0.1")

	state := e.loadStateFile()
	if len(state.Allowed) != 0 {
		t.Errorf("removed IP should be gone, got %d", len(state.Allowed))
	}
}

func TestEngineSaveSubnetEntry(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveSubnetEntry(SubnetEntry{CIDR: "192.168.0.0/16", Reason: "test"})

	state := e.loadStateFile()
	if len(state.BlockedNet) != 1 {
		t.Errorf("got %d subnets, want 1", len(state.BlockedNet))
	}
}

func TestEngineRemoveSubnetState(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveSubnetEntry(SubnetEntry{CIDR: "192.168.0.0/16", Reason: "test"})
	e.removeSubnetState("192.168.0.0/16")

	state := e.loadStateFile()
	if len(state.BlockedNet) != 0 {
		t.Errorf("removed subnet should be gone, got %d", len(state.BlockedNet))
	}
}

func TestEngineStatus(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{
		statePath: dir,
		cfg:       &FirewallConfig{Enabled: true, TCPIn: []int{22, 80}},
	}

	status := e.Status()
	if status == nil {
		t.Fatal("status should not be nil")
	}
}

func TestComputeInitialBlockStateRestoresPersistedSets(t *testing.T) {
	dir := t.TempDir()
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	writeEngineStateFile(t, dir, FirewallState{
		Blocked: []BlockedEntry{
			{IP: "203.0.113.5", Reason: "permanent", BlockedAt: time.Now()},
			{IP: "2001:db8::5", Reason: "temporary", BlockedAt: time.Now(), ExpiresAt: future},
			{IP: "198.51.100.9", Reason: "expired", BlockedAt: time.Now(), ExpiresAt: past},
			{IP: "not-an-ip", Reason: "invalid"},
		},
		Allowed: []AllowedEntry{
			{IP: "10.0.0.1", Reason: "manual", Source: SourceCLI},
			{IP: "10.0.0.1", Reason: "dns", Source: SourceDynDNS},
			{IP: "2001:db8::10", Reason: "admin"},
			{IP: "10.0.0.2", Reason: "expired", ExpiresAt: past},
			{IP: "bad-ip", Reason: "invalid"},
		},
		BlockedNet: []SubnetEntry{
			{CIDR: "198.51.100.0/24", Reason: "v4 net", BlockedAt: time.Now()},
			{CIDR: "2001:db8:1::/64", Reason: "v6 net", BlockedAt: time.Now()},
			{CIDR: "203.0.113.0/24", Reason: "expired", BlockedAt: time.Now(), ExpiresAt: past},
			{CIDR: "not-cidr", Reason: "invalid"},
		},
	})
	e := &Engine{statePath: dir, cfg: &FirewallConfig{IPv6: true}}

	e.mu.Lock()
	initial := e.computeInitialBlockStateLocked()
	e.mu.Unlock()

	if len(initial.blocked4) != 1 {
		t.Fatalf("blocked4 = %d, want 1", len(initial.blocked4))
	}
	requireElemKey(t, initial.blocked4[0], "203.0.113.5")
	if initial.blocked4[0].Timeout != 0 {
		t.Fatalf("permanent blocked4 timeout = %v, want 0", initial.blocked4[0].Timeout)
	}
	if len(initial.blocked6) != 1 {
		t.Fatalf("blocked6 = %d, want 1", len(initial.blocked6))
	}
	requireElemKey(t, initial.blocked6[0], "2001:db8::5")
	if initial.blocked6[0].Timeout <= 0 {
		t.Fatalf("temporary blocked6 timeout = %v, want > 0", initial.blocked6[0].Timeout)
	}
	if len(initial.allowed4) != 1 {
		t.Fatalf("allowed4 = %d, want 1", len(initial.allowed4))
	}
	requireElemKey(t, initial.allowed4[0], "10.0.0.1")
	if len(initial.allowed6) != 1 {
		t.Fatalf("allowed6 = %d, want 1", len(initial.allowed6))
	}
	requireElemKey(t, initial.allowed6[0], "2001:db8::10")
	requireIntervalElems(t, initial.blockedNet4, "198.51.100.0/24")
	requireIntervalElems(t, initial.blockedNet6, "2001:db8:1::/64")
}

func TestComputeInitialBlockStateSkipsIPv6WhenDisabled(t *testing.T) {
	dir := t.TempDir()
	writeEngineStateFile(t, dir, FirewallState{
		Blocked: []BlockedEntry{
			{IP: "203.0.113.5", Reason: "v4", BlockedAt: time.Now()},
			{IP: "2001:db8::5", Reason: "v6", BlockedAt: time.Now()},
		},
		Allowed: []AllowedEntry{
			{IP: "2001:db8::10", Reason: "v6"},
		},
		BlockedNet: []SubnetEntry{
			{CIDR: "2001:db8:1::/64", Reason: "v6 net", BlockedAt: time.Now()},
		},
	})
	e := &Engine{statePath: dir, cfg: &FirewallConfig{IPv6: false}}

	e.mu.Lock()
	initial := e.computeInitialBlockStateLocked()
	e.mu.Unlock()

	if len(initial.blocked4) != 1 {
		t.Fatalf("blocked4 = %d, want 1", len(initial.blocked4))
	}
	requireElemKey(t, initial.blocked4[0], "203.0.113.5")
	if len(initial.blocked6) != 0 || len(initial.allowed6) != 0 || len(initial.blockedNet6) != 0 {
		t.Fatalf("IPv6 elements restored while IPv6 disabled: blocked=%d allowed=%d nets=%d",
			len(initial.blocked6), len(initial.allowed6), len(initial.blockedNet6))
	}
}

func writeEngineStateFile(t *testing.T, dir string, state FirewallState) {
	t.Helper()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func requireElemKey(t *testing.T, elem nftables.SetElement, want string) {
	t.Helper()
	if !net.IP(elem.Key).Equal(net.ParseIP(want)) {
		t.Fatalf("element key = %v, want %s", net.IP(elem.Key), want)
	}
}

func requireIntervalElems(t *testing.T, elems []nftables.SetElement, cidr string) {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	if len(elems) != 2 {
		t.Fatalf("%s elements = %d, want 2", cidr, len(elems))
	}
	start := network.IP.To4()
	if start == nil {
		start = network.IP.To16()
	}
	if !net.IP(elems[0].Key).Equal(start) {
		t.Fatalf("%s start = %v, want %v", cidr, net.IP(elems[0].Key), start)
	}
	wantEnd := nextIP(lastIPInRange(network))
	if !elems[1].IntervalEnd || !net.IP(elems[1].Key).Equal(wantEnd) {
		t.Fatalf("%s end = {key:%v interval:%t}, want {key:%v interval:true}",
			cidr, net.IP(elems[1].Key), elems[1].IntervalEnd, wantEnd)
	}
}

func TestIntervalSetElementsSkipsSaturatedEnd(t *testing.T) {
	_, network, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	got := intervalSetElements(network.IP.To4(), lastIPInRange(network))
	if len(got) != 0 {
		t.Fatalf("0.0.0.0/0 elements = %d, want 0", len(got))
	}

	ip := net.ParseIP("255.255.255.255").To4()
	got = intervalSetElements(ip, ip)
	if len(got) != 0 {
		t.Fatalf("255.255.255.255/32 elements = %d, want 0", len(got))
	}
}

func TestComputeInitialBlockStateSkipsSaturatedCIDRs(t *testing.T) {
	dir := t.TempDir()
	writeEngineStateFile(t, dir, FirewallState{
		BlockedNet: []SubnetEntry{
			{CIDR: "0.0.0.0/0", Reason: "bad v4", BlockedAt: time.Now()},
			{CIDR: "::/0", Reason: "bad v6", BlockedAt: time.Now()},
			{CIDR: "198.51.100.0/24", Reason: "v4 net", BlockedAt: time.Now()},
			{CIDR: "2001:db8:1::/64", Reason: "v6 net", BlockedAt: time.Now()},
		},
	})
	e := &Engine{statePath: dir, cfg: &FirewallConfig{IPv6: true}}

	e.mu.Lock()
	initial := e.computeInitialBlockStateLocked()
	e.mu.Unlock()

	requireIntervalElems(t, initial.blockedNet4, "198.51.100.0/24")
	requireIntervalElems(t, initial.blockedNet6, "2001:db8:1::/64")
}

// TestResolveSubnetSetMalformedIPReturnsNil guards a defensive nil-end
// branch. A well-formed ParseCIDR result always yields a 4- or 16-byte
// IP, so lastIPInRange returns non-nil in normal operation. But a
// handcrafted net.IPNet with an 8-byte IP makes lastIPInRange return
// nil; without the guard, the caller would receive the broken end and
// nextIP(nil) would feed an empty Key to the kernel. The test populates
// both setBlockedNet and setBlockedNet6 with non-nil sentinels so the
// only path producing a nil return is the end-nil guard itself --
// removing that guard makes this test fail loudly.
func TestResolveSubnetSetMalformedIPReturnsNil(t *testing.T) {
	e := &Engine{
		setBlockedNet:  &nftables.Set{Name: "blocked_nets"},
		setBlockedNet6: &nftables.Set{Name: "blocked_nets6"},
	}
	broken := &net.IPNet{
		IP:   net.IP{1, 2, 3, 4, 5, 6, 7, 8}, // 8 bytes -> neither v4 nor v6
		Mask: net.CIDRMask(64, 128),
	}
	set, start, end := e.resolveSubnetSet(broken)
	if set != nil || start != nil || end != nil {
		t.Errorf("malformed net.IPNet should yield (nil, nil, nil), got (%v, %v, %v)", set, start, end)
	}
}
