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
	_ = e.saveState(state)

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

	_ = e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.5", Reason: "test"})

	state := e.loadStateFile()
	if len(state.Blocked) != 1 {
		t.Errorf("got %d blocked, want 1", len(state.Blocked))
	}
}

func TestEngineSaveBlockedEntryDedup(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	_ = e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.5", Reason: "first"})
	_ = e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.5", Reason: "second"})

	state := e.loadStateFile()
	if len(state.Blocked) != 1 {
		t.Errorf("dedup should keep 1, got %d", len(state.Blocked))
	}
	if state.Blocked[0].Reason != "second" {
		t.Errorf("should update reason, got %q", state.Blocked[0].Reason)
	}
}

func TestBlockedStateHelpersMatchIPv4MappedForms(t *testing.T) {
	state := FirewallState{
		Blocked: []BlockedEntry{
			{IP: "203.0.113.10", Reason: "old"},
			{IP: "::ffff:203.0.113.10", Reason: "duplicate"},
		},
	}

	upsertBlockedEntryInState(&state, BlockedEntry{IP: "::ffff:203.0.113.10", Reason: "new"})
	if len(state.Blocked) != 1 {
		t.Fatalf("blocked entries = %d, want 1", len(state.Blocked))
	}
	if state.Blocked[0].IP != "203.0.113.10" {
		t.Fatalf("stored IP = %q, want canonical 203.0.113.10", state.Blocked[0].IP)
	}
	if state.Blocked[0].Reason != "new" {
		t.Fatalf("reason = %q, want new", state.Blocked[0].Reason)
	}

	removeBlockedIPFromState(&state, "::ffff:203.0.113.10")
	if len(state.Blocked) != 0 {
		t.Fatalf("mapped remove left blocked entries: %+v", state.Blocked)
	}
}

func TestFirewallStateNormalizationCanonicalizesIPv4MappedRows(t *testing.T) {
	e := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{}}
	now := time.Now()
	state := FirewallState{
		Blocked: []BlockedEntry{
			{IP: "::ffff:203.0.113.10", Reason: "temporary", ExpiresAt: now.Add(time.Hour)},
			{IP: "203.0.113.10", Reason: "permanent"},
		},
		Allowed: []AllowedEntry{
			{IP: "::ffff:10.0.0.42", Source: SourceCLI, ExpiresAt: now.Add(time.Hour)},
			{IP: "10.0.0.42", Source: SourceCLI},
			{IP: "::ffff:10.0.0.42", Source: SourceDynDNS},
		},
		PortAllowed: []PortAllowEntry{
			{IP: "::ffff:10.0.0.50", Port: 993, Proto: "tcp", Reason: "mapped"},
			{IP: "10.0.0.50", Port: 993, Proto: "tcp", Reason: "duplicate"},
		},
	}
	if err := e.saveState(&state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	got := e.loadStateFile()
	if len(got.Blocked) != 1 || got.Blocked[0].IP != "203.0.113.10" || !got.Blocked[0].ExpiresAt.IsZero() {
		t.Fatalf("blocked rows = %+v, want one canonical permanent row", got.Blocked)
	}
	if len(got.Allowed) != 2 {
		t.Fatalf("allowed rows = %+v, want two sources for the canonical IP", got.Allowed)
	}
	for _, entry := range got.Allowed {
		if entry.IP != "10.0.0.42" {
			t.Fatalf("allowed IP = %q, want canonical 10.0.0.42", entry.IP)
		}
		if entry.Source == SourceCLI && !entry.ExpiresAt.IsZero() {
			t.Fatalf("CLI allow = %+v, want permanent row to win", entry)
		}
	}
	if len(got.PortAllowed) != 1 || got.PortAllowed[0].IP != "10.0.0.50" {
		t.Fatalf("port-allowed rows = %+v, want one canonical row", got.PortAllowed)
	}
}

func TestBlockedStateCountsDeduplicateIPv4MappedRows(t *testing.T) {
	state := FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.10"},
		{IP: "::ffff:203.0.113.10", ExpiresAt: time.Now().Add(time.Hour)},
		{IP: "::ffff:203.0.113.11", ExpiresAt: time.Now().Add(time.Hour)},
		{IP: "203.0.113.11", ExpiresAt: time.Now().Add(2 * time.Hour)},
		{IP: "not-an-ip"},
	}}

	perm, temp := blockedStatePermTempCounts(state, "")
	if perm != 1 || temp != 1 {
		t.Fatalf("counts = perm %d temp %d, want perm 1 temp 1", perm, temp)
	}
	if got := countPermanentBlockedEntries(state); got != 1 {
		t.Fatalf("permanent count = %d, want 1", got)
	}
	perm, temp = blockedStatePermTempCounts(state, "::ffff:203.0.113.10")
	if perm != 0 || temp != 1 {
		t.Fatalf("excluded counts = perm %d temp %d, want perm 0 temp 1", perm, temp)
	}
}

func TestInitialBlockStateDeduplicatesIPv4MappedRows(t *testing.T) {
	e := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{IPv6: true}}
	if err := e.saveState(&FirewallState{Blocked: []BlockedEntry{
		{IP: "::ffff:203.0.113.10", Reason: "mapped"},
		{IP: "203.0.113.10", Reason: "canonical"},
	}}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	ibs := e.computeInitialBlockStateLocked()
	if len(ibs.blocked4) != 1 {
		t.Fatalf("IPv4 blocked elements = %d, want 1", len(ibs.blocked4))
	}
	if got := net.IP(ibs.blocked4[0].Key).String(); got != "203.0.113.10" {
		t.Fatalf("blocked key = %q, want 203.0.113.10", got)
	}
}

func TestEngineRemoveBlockedState(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	_ = e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.5", Reason: "test"})
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

// TestEngineBlockedSubnets verifies that BlockedSubnets returns a copy of the
// persisted subnet entries without exposing internal state. The mutation is
// proved against a WARM state cache: the first call populates the shared cache
// (ensureStateCacheLocked), the caller mutates the returned slice, and a second
// call must still read the original data. An aliasing implementation would let
// the mutation corrupt the cache and surface on the warm read.
func TestEngineBlockedSubnets(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	// Persist two subnet entries with different sources.
	autoEntry := SubnetEntry{
		CIDR:      "198.51.100.0/24",
		Reason:    "http_asn_crawl",
		Source:    SourceAutoResponse,
		BlockedAt: time.Now().Truncate(time.Second),
	}
	webuiEntry := SubnetEntry{
		CIDR:      "203.0.113.0/24",
		Reason:    "operator block",
		Source:    SourceWebUI,
		BlockedAt: time.Now().Truncate(time.Second),
	}
	e.saveSubnetEntry(autoEntry)
	e.saveSubnetEntry(webuiEntry)

	// First call warms the shared state cache and returns a snapshot.
	first := e.BlockedSubnets()
	if len(first) != 2 {
		t.Fatalf("BlockedSubnets: want 2 entries, got %d", len(first))
	}

	// Mutate every element of the returned slice. With a warm cache, an aliasing
	// implementation would let this corrupt the cached engine state.
	for i := range first {
		first[i].CIDR = "mutated"
		first[i].Source = "mutated"
	}

	// Second call hits the WARM cache. If BlockedSubnets aliased internal state,
	// these reads would now return "mutated".
	second := e.BlockedSubnets()
	if len(second) != 2 {
		t.Fatalf("BlockedSubnets (warm): want 2 entries, got %d", len(second))
	}
	for _, entry := range second {
		if entry.CIDR == "mutated" || entry.Source == "mutated" {
			t.Fatalf("BlockedSubnets: warm-cache read returned mutated state %+v — slice is not a copy", entry)
		}
	}

	// Source field must be preserved across the warm read.
	sources := make(map[string]int)
	for _, entry := range second {
		sources[entry.Source]++
	}
	if sources[SourceAutoResponse] != 1 {
		t.Errorf("want 1 auto_response entry, got %d", sources[SourceAutoResponse])
	}
	if sources[SourceWebUI] != 1 {
		t.Errorf("want 1 web_ui entry, got %d", sources[SourceWebUI])
	}
}
