//go:build linux

package firewall

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These tests cover helpers in engine.go that do not require a real nftables
// conn. They exercise state/JSON plumbing, IP resolution, and pure-Go helpers.

// --- resolveIPSet ---

func TestEngineResolveIPSetInvalidIP(t *testing.T) {
	e := &Engine{}
	_, _, err := e.resolveIPSet("not-an-ip", nil, nil)
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestEngineResolveIPSetIPv4Returns4Set(t *testing.T) {
	e := &Engine{}
	// resolveIPSet expects *nftables.Set; pass nil for both and verify the
	// v4 path returns (nil, key, nil) — i.e. no error + 4-byte key.
	set, key, err := e.resolveIPSet("203.0.113.5", nil, nil)
	if err != nil {
		t.Fatalf("v4 resolve: %v", err)
	}
	if set != nil {
		t.Errorf("v4 set should be nil (we passed nil)")
	}
	if len(key) != 4 {
		t.Errorf("key len = %d, want 4", len(key))
	}
}

func TestEngineResolveIPSetIPv6RequiresSet6(t *testing.T) {
	e := &Engine{}
	// IPv6 with nil set6 = error
	_, _, err := e.resolveIPSet("2001:db8::1", nil, nil)
	if err == nil {
		t.Error("expected error when IPv6 passed but set6 is nil")
	}
}

// --- resolveSubnetSet ---

func TestEngineResolveSubnetSetIPv4(t *testing.T) {
	e := &Engine{}
	_, network, _ := net.ParseCIDR("203.0.113.0/24")
	set, start, end := e.resolveSubnetSet(network)
	if set != nil {
		t.Errorf("set should equal engine's nil setBlockedNet")
	}
	if start == nil || end == nil {
		t.Error("start/end should not be nil for IPv4 CIDR")
	}
}

func TestEngineResolveSubnetSetIPv6NilWhenDisabled(t *testing.T) {
	e := &Engine{} // setBlockedNet6 == nil → IPv6 disabled
	_, network, _ := net.ParseCIDR("2001:db8::/32")
	set, _, _ := e.resolveSubnetSet(network)
	if set != nil {
		t.Error("IPv6 subnet with nil set6 should return nil set")
	}
}

// --- loadCountryCIDRs extras ---

func TestLoadCountryCIDRsSkipsInvalidAndComments(t *testing.T) {
	dir := t.TempDir()
	body := "# comment line\n\n" +
		"not-a-cidr\n" +
		"203.0.113.0/24\n"
	_ = os.WriteFile(filepath.Join(dir, "ZZ.cidr"), []byte(body), 0644)

	elems := loadCountryCIDRs(dir, "zz") // lower-case, should upper
	if len(elems) != 2 {
		t.Errorf("expected 2 elements (one valid CIDR), got %d", len(elems))
	}
}

func TestLoadCountryCIDRsCaseInsensitiveCountry(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "DE.cidr"), []byte("10.0.0.0/8\n"), 0644)

	lower := loadCountryCIDRs(dir, "de")
	upper := loadCountryCIDRs(dir, "DE")
	if len(lower) != len(upper) {
		t.Errorf("case should not matter: lower=%d upper=%d", len(lower), len(upper))
	}
}

// --- loadStateFile prune semantics ---

func TestEngineLoadStateFilePrunesExpiredSubnets(t *testing.T) {
	dir := t.TempDir()
	state := FirewallState{
		BlockedNet: []SubnetEntry{
			{CIDR: "192.168.0.0/16", Reason: "active"},
			{CIDR: "10.0.0.0/8", Reason: "expired", ExpiresAt: time.Now().Add(-time.Hour)},
		},
	}
	data, _ := json.Marshal(state)
	_ = os.WriteFile(filepath.Join(dir, "state.json"), data, 0600)

	e := &Engine{statePath: dir}
	loaded := e.loadStateFile()
	if len(loaded.BlockedNet) != 1 {
		t.Errorf("expired subnet should be pruned, got %d", len(loaded.BlockedNet))
	}
	if loaded.BlockedNet[0].CIDR != "192.168.0.0/16" {
		t.Errorf("wrong subnet kept: %s", loaded.BlockedNet[0].CIDR)
	}
}

func TestEngineLoadStateFilePrunesExpiredAllowed(t *testing.T) {
	dir := t.TempDir()
	state := FirewallState{
		Allowed: []AllowedEntry{
			{IP: "10.0.0.1", Reason: "permanent"},
			{IP: "10.0.0.2", Reason: "expired", ExpiresAt: time.Now().Add(-time.Hour)},
			{IP: "10.0.0.3", Reason: "future", ExpiresAt: time.Now().Add(time.Hour)},
		},
	}
	data, _ := json.Marshal(state)
	_ = os.WriteFile(filepath.Join(dir, "state.json"), data, 0600)

	e := &Engine{statePath: dir}
	loaded := e.loadStateFile()
	if len(loaded.Allowed) != 2 {
		t.Errorf("expected 2 active entries, got %d", len(loaded.Allowed))
	}
}

func TestEngineLoadStateFileBadJSONReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "state.json"), []byte("{not json"), 0600)

	e := &Engine{statePath: dir}
	loaded := e.loadStateFile()
	if len(loaded.Blocked) != 0 || len(loaded.Allowed) != 0 || len(loaded.BlockedNet) != 0 {
		t.Error("malformed JSON should produce empty state")
	}
}

// --- saveBlockedEntry / saveAllowedEntry provenance autofill ---

func TestEngineSaveBlockedEntryInfersSourceWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveBlockedEntry(BlockedEntry{
		IP:     "203.0.113.7",
		Reason: "via CLI",
	})

	state := e.loadStateFile()
	if len(state.Blocked) != 1 {
		t.Fatalf("expected 1 blocked entry, got %d", len(state.Blocked))
	}
	if state.Blocked[0].Source != SourceCLI {
		t.Errorf("source should be inferred to %q, got %q", SourceCLI, state.Blocked[0].Source)
	}
}

func TestEngineSaveAllowedEntryInfersSourceWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveAllowedEntry(AllowedEntry{
		IP:     "10.0.0.42",
		Reason: "bulk whitelist",
	})

	state := e.loadStateFile()
	if len(state.Allowed) != 1 {
		t.Fatalf("expected 1 allowed entry, got %d", len(state.Allowed))
	}
	if state.Allowed[0].Source != SourceWhitelist {
		t.Errorf("source should be inferred to %q, got %q", SourceWhitelist, state.Allowed[0].Source)
	}
}

func TestEngineSaveAllowedEntryDedupSameSource(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "first", Source: SourceCLI})
	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "updated", Source: SourceCLI})

	state := e.loadStateFile()
	if len(state.Allowed) != 1 {
		t.Errorf("same ip+source should dedup: got %d", len(state.Allowed))
	}
	if state.Allowed[0].Reason != "updated" {
		t.Errorf("reason should be updated, got %q", state.Allowed[0].Reason)
	}
}

func TestEngineSaveAllowedEntryDifferentSourceKeepsBoth(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "a", Source: SourceCLI})
	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "b", Source: SourceDynDNS})

	state := e.loadStateFile()
	if len(state.Allowed) != 2 {
		t.Errorf("different sources should coexist: got %d", len(state.Allowed))
	}
}

func TestEngineSaveSubnetEntryDedupCIDR(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveSubnetEntry(SubnetEntry{CIDR: "192.168.0.0/16", Reason: "first"})
	e.saveSubnetEntry(SubnetEntry{CIDR: "192.168.0.0/16", Reason: "second"})

	state := e.loadStateFile()
	if len(state.BlockedNet) != 1 {
		t.Errorf("dup CIDR should not append: got %d", len(state.BlockedNet))
	}
	// Note: for subnets, the existing entry wins; second is dropped.
	if state.BlockedNet[0].Reason != "first" {
		t.Errorf("first entry should be retained, got %q", state.BlockedNet[0].Reason)
	}
}

func TestEngineSaveSubnetEntryInfersSource(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveSubnetEntry(SubnetEntry{CIDR: "10.0.0.0/8", Reason: "via CSM Web UI"})
	state := e.loadStateFile()
	if state.BlockedNet[0].Source != SourceWebUI {
		t.Errorf("source should be inferred to %q, got %q", SourceWebUI, state.BlockedNet[0].Source)
	}
}

// --- removeAllowedStateBySource edge cases ---

func TestEngineRemoveAllowedStateBySourceEmptyState(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	if removed := e.removeAllowedStateBySource("10.0.0.1", SourceCLI); removed {
		t.Error("no state → should return false")
	}
}

func TestEngineRemoveAllowedStateBySourceNoMatchingSource(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Source: SourceCLI})
	if removed := e.removeAllowedStateBySource("10.0.0.1", SourceDynDNS); removed {
		t.Error("no entry for that ip+source → should return false")
	}
	// And the CLI entry should still be present.
	state := e.loadStateFile()
	if len(state.Allowed) != 1 {
		t.Errorf("untouched entry should remain: got %d", len(state.Allowed))
	}
}

// --- saveState atomicity (rename write) ---

func TestEngineSaveStateAtomicRename(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}
	e.saveState(&FirewallState{
		Blocked: []BlockedEntry{{IP: "1.2.3.4"}},
	})

	// Must produce a clean state.json, no leftover .tmp
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var hasState, hasTmp bool
	for _, entry := range entries {
		if entry.Name() == "state.json" {
			hasState = true
		}
		if filepath.Ext(entry.Name()) == ".tmp" {
			hasTmp = true
		}
	}
	if !hasState {
		t.Error("state.json must exist")
	}
	if hasTmp {
		t.Error("leftover .tmp file — rename failed")
	}
}

// --- Status passthrough ---

func TestEngineStatusIncludesConfigFields(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{
		statePath: dir,
		cfg: &FirewallConfig{
			Enabled:    true,
			TCPIn:      []int{22, 80, 443},
			LogDropped: true,
			InfraIPs:   []string{"10.0.0.0/8"},
		},
	}
	status := e.Status()
	if status["enabled"] != true {
		t.Errorf("enabled = %v", status["enabled"])
	}
	if status["log_dropped"] != true {
		t.Errorf("log_dropped = %v", status["log_dropped"])
	}
	if v, ok := status["blocked"].(int); !ok || v != 0 {
		t.Errorf("blocked = %v (%T)", status["blocked"], status["blocked"])
	}
}

// --- CleanExpiredAllows with only active entries keeps state unchanged ---

func TestEngineCleanExpiredAllowsActiveOnly(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{
		statePath: dir,
		cfg:       &FirewallConfig{Enabled: true},
	}
	e.saveAllowedEntry(AllowedEntry{
		IP:        "10.0.0.1",
		Reason:    "future",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	n := e.CleanExpiredAllows()
	if n != 0 {
		t.Errorf("no expired entries → CleanExpiredAllows should return 0, got %d", n)
	}
	state := e.loadStateFile()
	if len(state.Allowed) != 1 {
		t.Errorf("unexpired entry should survive, got %d", len(state.Allowed))
	}
}

func TestEngineCleanExpiredSubnetsActiveOnly(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{
		statePath: dir,
		cfg:       &FirewallConfig{Enabled: true},
	}
	e.saveSubnetEntry(SubnetEntry{
		CIDR:      "192.168.0.0/16",
		Reason:    "future",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	n := e.CleanExpiredSubnets()
	if n != 0 {
		t.Errorf("no expired subnets → should return 0, got %d", n)
	}
}
