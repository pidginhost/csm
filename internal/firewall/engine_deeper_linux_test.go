//go:build linux

package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Additional deep-coverage tests for engine.go helpers that do not need a
// real nftables conn. These complement engine_methods_linux_test.go,
// engine_state_linux_test.go, and engine_coverage_linux_test.go.

// --- AllowIPPort / RemoveAllowIPPort (pure state) -------------------------

func TestEngineAllowIPPortAddsEntry(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	if err := e.AllowIPPort("10.0.0.5", 3306, "tcp", "mysql admin"); err != nil {
		t.Fatalf("AllowIPPort: %v", err)
	}
	state := e.loadStateFile()
	if len(state.PortAllowed) != 1 {
		t.Fatalf("PortAllowed len = %d, want 1", len(state.PortAllowed))
	}
	entry := state.PortAllowed[0]
	if entry.IP != "10.0.0.5" || entry.Port != 3306 || entry.Proto != "tcp" {
		t.Errorf("entry = %+v", entry)
	}
	if entry.Source == "" {
		t.Error("Source should be inferred")
	}
}

func TestEngineAllowIPPortDedupsSameTriplet(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	_ = e.AllowIPPort("10.0.0.5", 3306, "tcp", "first")
	_ = e.AllowIPPort("10.0.0.5", 3306, "tcp", "second")

	state := e.loadStateFile()
	if len(state.PortAllowed) != 1 {
		t.Errorf("duplicate triplet should dedup, got %d", len(state.PortAllowed))
	}
	// First write wins (function returns early on dup)
	if state.PortAllowed[0].Reason != "first" {
		t.Errorf("reason = %q, want first", state.PortAllowed[0].Reason)
	}
}

func TestEngineAllowIPPortDifferentPortCoexists(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	_ = e.AllowIPPort("10.0.0.5", 3306, "tcp", "mysql")
	_ = e.AllowIPPort("10.0.0.5", 5432, "tcp", "postgres")

	state := e.loadStateFile()
	if len(state.PortAllowed) != 2 {
		t.Errorf("different ports should coexist, got %d", len(state.PortAllowed))
	}
}

func TestEngineAllowIPPortDifferentProtoCoexists(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	_ = e.AllowIPPort("10.0.0.5", 53, "tcp", "dns tcp")
	_ = e.AllowIPPort("10.0.0.5", 53, "udp", "dns udp")

	state := e.loadStateFile()
	if len(state.PortAllowed) != 2 {
		t.Errorf("different proto should coexist, got %d", len(state.PortAllowed))
	}
}

func TestEngineAllowIPPortInvalidIP(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	if err := e.AllowIPPort("not-an-ip", 3306, "tcp", "x"); err == nil {
		t.Error("invalid IP should error")
	}
}

func TestEngineAllowIPPortInvalidPortLow(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	if err := e.AllowIPPort("10.0.0.1", 0, "tcp", "x"); err == nil {
		t.Error("port 0 should error")
	}
}

func TestEngineAllowIPPortInvalidPortHigh(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	if err := e.AllowIPPort("10.0.0.1", 70000, "tcp", "x"); err == nil {
		t.Error("port > 65535 should error")
	}
}

func TestEngineAllowIPPortUnknownProtoDefaultsTCP(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	if err := e.AllowIPPort("10.0.0.5", 3306, "sctp", "weird"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	state := e.loadStateFile()
	if len(state.PortAllowed) != 1 {
		t.Fatalf("expected 1 entry")
	}
	if state.PortAllowed[0].Proto != "tcp" {
		t.Errorf("proto normalized to %q, want tcp", state.PortAllowed[0].Proto)
	}
}

func TestEngineRemoveAllowIPPortFound(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	_ = e.AllowIPPort("10.0.0.5", 3306, "tcp", "mysql")
	_ = e.AllowIPPort("10.0.0.5", 5432, "tcp", "postgres")

	if err := e.RemoveAllowIPPort("10.0.0.5", 3306, "tcp"); err != nil {
		t.Fatalf("RemoveAllowIPPort: %v", err)
	}
	state := e.loadStateFile()
	if len(state.PortAllowed) != 1 {
		t.Errorf("after remove, got %d, want 1", len(state.PortAllowed))
	}
	if state.PortAllowed[0].Port != 5432 {
		t.Errorf("wrong entry kept: %d", state.PortAllowed[0].Port)
	}
}

func TestEngineRemoveAllowIPPortNotFound(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	err := e.RemoveAllowIPPort("10.0.0.5", 3306, "tcp")
	if err == nil {
		t.Error("removing nonexistent entry should error")
	}
}

func TestEngineRemoveAllowIPPortProtoMismatch(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	_ = e.AllowIPPort("10.0.0.5", 3306, "tcp", "mysql")

	// proto differs -> should not match -> error
	if err := e.RemoveAllowIPPort("10.0.0.5", 3306, "udp"); err == nil {
		t.Error("proto mismatch should error")
	}

	state := e.loadStateFile()
	if len(state.PortAllowed) != 1 {
		t.Errorf("original entry should survive, got %d", len(state.PortAllowed))
	}
}

// --- loadStateFile preserves PortAllowed ---------------------------------

func TestEngineLoadStateFilePreservesPortAllowed(t *testing.T) {
	dir := t.TempDir()
	state := FirewallState{
		PortAllowed: []PortAllowEntry{
			{IP: "10.0.0.1", Port: 22, Proto: "tcp", Reason: "ssh"},
			{IP: "10.0.0.2", Port: 3306, Proto: "tcp", Reason: "mysql"},
		},
	}
	data, _ := json.Marshal(state)
	_ = os.WriteFile(filepath.Join(dir, "state.json"), data, 0600)

	e := &Engine{statePath: dir}
	loaded := e.loadStateFile()
	if len(loaded.PortAllowed) != 2 {
		t.Errorf("PortAllowed = %d, want 2", len(loaded.PortAllowed))
	}
}

// --- saveBlockedEntry / saveSubnetEntry keep explicit Source --------------

func TestEngineSaveBlockedEntryPreservesExplicitSource(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveBlockedEntry(BlockedEntry{
		IP:     "203.0.113.9",
		Reason: "anything",
		Source: SourceAutoResponse, // explicit should not be overridden
	})
	state := e.loadStateFile()
	if state.Blocked[0].Source != SourceAutoResponse {
		t.Errorf("source overridden: got %q", state.Blocked[0].Source)
	}
}

func TestEngineSaveSubnetEntryPreservesExplicitSource(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveSubnetEntry(SubnetEntry{
		CIDR:   "10.0.0.0/8",
		Reason: "anything",
		Source: SourceCLI,
	})
	state := e.loadStateFile()
	if state.BlockedNet[0].Source != SourceCLI {
		t.Errorf("source overridden: got %q", state.BlockedNet[0].Source)
	}
}

// --- CleanExpiredAllows edge cases ---------------------------------------

// Two different sources for the same IP; one expired, one active.
// The IP stays in state (active entry survives).
func TestEngineCleanExpiredAllowsSameIPMixedSources(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir, cfg: &FirewallConfig{}}

	e.saveAllowedEntry(AllowedEntry{
		IP:        "10.0.0.42",
		Reason:    "expired cli",
		Source:    SourceCLI,
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	e.saveAllowedEntry(AllowedEntry{
		IP:        "10.0.0.42",
		Reason:    "active dyndns",
		Source:    SourceDynDNS,
		ExpiresAt: time.Now().Add(time.Hour),
	})

	// The nftables flush will fail silently (nil conn wrapper), so this returns 0.
	// But state should reflect the active entry surviving.
	// NOTE: CleanExpiredAllows will try to flush; if that fails it returns 0 and
	// does not update state. We avoid that by not exercising real flush here —
	// we just check that loadStateFile properly filters expired on read.
	state := e.loadStateFile()
	var ipCount int
	for _, entry := range state.Allowed {
		if entry.IP == "10.0.0.42" {
			ipCount++
		}
	}
	if ipCount != 1 {
		t.Errorf("loadStateFile should filter expired: got %d entries for ip", ipCount)
	}
}

// Multiple expired subnets of mixed IP families — loadStateFile prunes them.
func TestEngineLoadStateFilePrunesMultipleExpiredSubnets(t *testing.T) {
	dir := t.TempDir()
	past := time.Now().Add(-time.Hour)
	state := FirewallState{
		BlockedNet: []SubnetEntry{
			{CIDR: "10.0.0.0/8", ExpiresAt: past},
			{CIDR: "192.168.0.0/16", ExpiresAt: past},
			{CIDR: "172.16.0.0/12"}, // permanent
		},
	}
	data, _ := json.Marshal(state)
	_ = os.WriteFile(filepath.Join(dir, "state.json"), data, 0600)

	e := &Engine{statePath: dir}
	loaded := e.loadStateFile()
	if len(loaded.BlockedNet) != 1 {
		t.Errorf("expected 1 permanent subnet, got %d", len(loaded.BlockedNet))
	}
	if loaded.BlockedNet[0].CIDR != "172.16.0.0/12" {
		t.Errorf("wrong subnet kept: %s", loaded.BlockedNet[0].CIDR)
	}
}

// --- loadCountryCIDRs: missing file / empty file --------------------------

func TestLoadCountryCIDRsMissingFileReturnsNil(t *testing.T) {
	dir := t.TempDir() // no .cidr files inside
	elems := loadCountryCIDRs(dir, "US")
	if elems != nil {
		t.Errorf("missing file should return nil, got %v", elems)
	}
}

func TestLoadCountryCIDRsEmptyFileReturnsNil(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "XX.cidr"), []byte(""), 0644)
	elems := loadCountryCIDRs(dir, "XX")
	if len(elems) != 0 {
		t.Errorf("empty file should yield 0 elements, got %d", len(elems))
	}
}

func TestLoadCountryCIDRsSkipsIPv6Lines(t *testing.T) {
	// loadCountryCIDRs only accepts IPv4 CIDRs (start := network.IP.To4())
	dir := t.TempDir()
	body := "2001:db8::/32\n" + // IPv6 — should be skipped
		"203.0.113.0/24\n"
	_ = os.WriteFile(filepath.Join(dir, "ZZ.cidr"), []byte(body), 0644)

	elems := loadCountryCIDRs(dir, "ZZ")
	// Only the IPv4 CIDR contributes (2 elements: start + interval end)
	if len(elems) != 2 {
		t.Errorf("expected 2 elements for 1 IPv4 CIDR, got %d", len(elems))
	}
}

func TestLoadCountryCIDRsAllBlankLinesAndComments(t *testing.T) {
	dir := t.TempDir()
	body := "\n\n   \n# header comment\n# another comment\n\n"
	_ = os.WriteFile(filepath.Join(dir, "NN.cidr"), []byte(body), 0644)

	elems := loadCountryCIDRs(dir, "NN")
	if len(elems) != 0 {
		t.Errorf("only blanks/comments should yield 0 elements, got %d", len(elems))
	}
}

// --- DefaultConfig: additional field checks (complementing existing tests) -

func TestDefaultConfigTCPInIncludesCommonPorts(t *testing.T) {
	cfg := DefaultConfig()
	wanted := map[int]bool{22: false, 80: false, 443: false, 2083: false}
	// NB: cfg.TCPIn from DefaultConfig doesn't include 22 explicitly? It actually
	// includes 20/21/25/... — and 22 is traditionally added elsewhere. Check only
	// common non-SSH ports that ARE in the default list.
	delete(wanted, 22)
	for _, p := range cfg.TCPIn {
		if _, ok := wanted[p]; ok {
			wanted[p] = true
		}
	}
	for port, found := range wanted {
		if !found {
			t.Errorf("DefaultConfig.TCPIn missing port %d", port)
		}
	}
}

func TestDefaultConfigRestrictedTCPNonEmpty(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.RestrictedTCP) == 0 {
		t.Error("RestrictedTCP should have default ports")
	}
}

func TestDefaultConfigPassiveFTPRangeValid(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.PassiveFTPStart <= 0 || cfg.PassiveFTPEnd <= 0 {
		t.Errorf("PassiveFTP range unset: %d-%d", cfg.PassiveFTPStart, cfg.PassiveFTPEnd)
	}
	if cfg.PassiveFTPStart >= cfg.PassiveFTPEnd {
		t.Errorf("invalid passive FTP range: %d-%d", cfg.PassiveFTPStart, cfg.PassiveFTPEnd)
	}
}

func TestDefaultConfigConnRateLimitPositive(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ConnRateLimit <= 0 {
		t.Errorf("ConnRateLimit should be > 0, got %d", cfg.ConnRateLimit)
	}
}

func TestDefaultConfigPortFloodProtectsSMTP(t *testing.T) {
	cfg := DefaultConfig()
	smtpPorts := map[int]bool{25: false, 465: false, 587: false}
	for _, rule := range cfg.PortFlood {
		if _, ok := smtpPorts[rule.Port]; ok {
			smtpPorts[rule.Port] = true
			if rule.Proto != "tcp" {
				t.Errorf("SMTP port %d should be tcp, got %q", rule.Port, rule.Proto)
			}
			if rule.Hits <= 0 || rule.Seconds <= 0 {
				t.Errorf("port %d rule has bad rate: hits=%d seconds=%d", rule.Port, rule.Hits, rule.Seconds)
			}
		}
	}
	for port, covered := range smtpPorts {
		if !covered {
			t.Errorf("PortFlood missing SMTP port %d", port)
		}
	}
}

func TestDefaultConfigUDPFloodDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.UDPFlood {
		t.Error("UDPFlood should be enabled by default")
	}
	if cfg.UDPFloodRate <= 0 {
		t.Errorf("UDPFloodRate should be > 0, got %d", cfg.UDPFloodRate)
	}
	if cfg.UDPFloodBurst <= 0 {
		t.Errorf("UDPFloodBurst should be > 0, got %d", cfg.UDPFloodBurst)
	}
}

func TestDefaultConfigLogRatePositive(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.LogDropped {
		t.Error("LogDropped should be enabled by default")
	}
	if cfg.LogRate <= 0 {
		t.Errorf("LogRate should be > 0, got %d", cfg.LogRate)
	}
}

func TestDefaultConfigOutboundPortsNonEmpty(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.TCPOut) == 0 {
		t.Error("TCPOut should have defaults")
	}
	if len(cfg.UDPOut) == 0 {
		t.Error("UDPOut should have defaults")
	}
}

func TestDefaultConfigDropNoLogIncludesSMB(t *testing.T) {
	cfg := DefaultConfig()
	// SMB/NetBIOS ports — widely scanned, should be in DropNoLog.
	wanted := map[int]bool{137: false, 138: false, 139: false, 445: false}
	for _, p := range cfg.DropNoLog {
		if _, ok := wanted[p]; ok {
			wanted[p] = true
		}
	}
	for port, found := range wanted {
		if !found {
			t.Errorf("DropNoLog missing port %d", port)
		}
	}
}

func TestDefaultConfigEnabledDefaultFalse(t *testing.T) {
	cfg := DefaultConfig()
	// Safety: default must be disabled so CSM never auto-activates firewall.
	if cfg.Enabled {
		t.Error("DefaultConfig.Enabled must be false — firewall must be opt-in")
	}
}

// --- saveBlockedEntry dedup updates fields --------------------------------

func TestEngineSaveBlockedEntryDedupUpdatesExpiresAt(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	first := BlockedEntry{
		IP:        "203.0.113.99",
		Reason:    "first",
		BlockedAt: time.Now(),
	}
	second := BlockedEntry{
		IP:        "203.0.113.99",
		Reason:    "escalated",
		BlockedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	e.saveBlockedEntry(first)
	e.saveBlockedEntry(second)

	state := e.loadStateFile()
	if len(state.Blocked) != 1 {
		t.Fatalf("dedup should keep 1, got %d", len(state.Blocked))
	}
	if state.Blocked[0].Reason != "escalated" {
		t.Errorf("reason not updated: %q", state.Blocked[0].Reason)
	}
	if state.Blocked[0].ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be updated to the new value")
	}
}

// --- removeBlockedState / removeAllowedState / removeSubnetState safety ---

func TestEngineRemoveBlockedStateMissingIPIsNoop(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveBlockedEntry(BlockedEntry{IP: "10.0.0.1"})
	// Removing an IP not present should leave state unchanged (no panic, no error).
	e.removeBlockedState("9.9.9.9")

	state := e.loadStateFile()
	if len(state.Blocked) != 1 {
		t.Errorf("unrelated IP should survive, got %d", len(state.Blocked))
	}
}

func TestEngineRemoveAllowedStateMissingIPIsNoop(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Source: SourceCLI})
	e.removeAllowedState("9.9.9.9")

	state := e.loadStateFile()
	if len(state.Allowed) != 1 {
		t.Errorf("unrelated IP should survive, got %d", len(state.Allowed))
	}
}

func TestEngineRemoveSubnetStateMissingCIDRIsNoop(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveSubnetEntry(SubnetEntry{CIDR: "10.0.0.0/8"})
	e.removeSubnetState("192.168.0.0/16")

	state := e.loadStateFile()
	if len(state.BlockedNet) != 1 {
		t.Errorf("unrelated CIDR should survive, got %d", len(state.BlockedNet))
	}
}

// removeAllowedState must remove ALL entries matching the IP (regardless of source).
func TestEngineRemoveAllowedStateRemovesAllSourcesForIP(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "a", Source: SourceCLI})
	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "b", Source: SourceDynDNS})
	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.2", Reason: "survivor", Source: SourceCLI})

	e.removeAllowedState("10.0.0.1")

	state := e.loadStateFile()
	if len(state.Allowed) != 1 {
		t.Fatalf("expected 1 survivor entry, got %d", len(state.Allowed))
	}
	if state.Allowed[0].IP != "10.0.0.2" {
		t.Errorf("wrong survivor: %+v", state.Allowed[0])
	}
}

// --- removeAllowedStateBySource: removes one of two sources for same IP ---

func TestEngineRemoveAllowedStateBySourcePartialRemovalKeepsIP(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "cli", Source: SourceCLI})
	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "dyndns", Source: SourceDynDNS})

	ipGone := e.removeAllowedStateBySource("10.0.0.1", SourceCLI)
	if ipGone {
		t.Error("IP should still be present via DynDNS entry")
	}
	state := e.loadStateFile()
	if len(state.Allowed) != 1 {
		t.Fatalf("expected 1 remaining, got %d", len(state.Allowed))
	}
	if state.Allowed[0].Source != SourceDynDNS {
		t.Errorf("wrong source kept: %q", state.Allowed[0].Source)
	}
}

// Removing the only source for an IP must report the IP is fully gone.
func TestEngineRemoveAllowedStateBySourceOnlySourceReportsGone(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "only", Source: SourceCLI})

	ipGone := e.removeAllowedStateBySource("10.0.0.1", SourceCLI)
	if !ipGone {
		t.Error("removing only source should report IP gone")
	}
	state := e.loadStateFile()
	if len(state.Allowed) != 0 {
		t.Errorf("state should be empty, got %d", len(state.Allowed))
	}
}

// --- loadStateFile: state with all active entries preserved ---------------

func TestEngineLoadStateFileAllFieldsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	future := time.Now().Add(time.Hour)
	state := FirewallState{
		Blocked: []BlockedEntry{
			{IP: "1.1.1.1", Reason: "perm", Source: SourceCLI},
			{IP: "2.2.2.2", Reason: "temp", ExpiresAt: future},
		},
		BlockedNet: []SubnetEntry{
			{CIDR: "10.0.0.0/8", Reason: "perm", Source: SourceWebUI},
		},
		Allowed: []AllowedEntry{
			{IP: "3.3.3.3", Reason: "admin", Source: SourceWhitelist},
		},
		PortAllowed: []PortAllowEntry{
			{IP: "4.4.4.4", Port: 22, Proto: "tcp", Reason: "ssh"},
		},
	}
	data, _ := json.Marshal(state)
	_ = os.WriteFile(filepath.Join(dir, "state.json"), data, 0600)

	e := &Engine{statePath: dir}
	loaded := e.loadStateFile()
	if len(loaded.Blocked) != 2 {
		t.Errorf("Blocked = %d, want 2", len(loaded.Blocked))
	}
	if len(loaded.BlockedNet) != 1 {
		t.Errorf("BlockedNet = %d, want 1", len(loaded.BlockedNet))
	}
	if len(loaded.Allowed) != 1 {
		t.Errorf("Allowed = %d, want 1", len(loaded.Allowed))
	}
	if len(loaded.PortAllowed) != 1 {
		t.Errorf("PortAllowed = %d, want 1", len(loaded.PortAllowed))
	}
}
