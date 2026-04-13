package firewall

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- AppendAudit edge cases -----------------------------------------------

func TestAppendAuditBadDirDoesNotPanic(t *testing.T) {
	// statePath that doesn't exist — AppendAudit should silently return.
	AppendAudit(filepath.Join(t.TempDir(), "no", "such", "dir"), "block", "1.1.1.1", "test", "cli", 0)
	// No panic, no file created. Just verifying it doesn't blow up.
}

func TestAppendAuditExplicitSourceSkipsInference(t *testing.T) {
	fwDir := filepath.Join(t.TempDir(), "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}
	AppendAudit(fwDir, "block", "1.2.3.4", "some reason", "explicit_source", 0)

	data, err := os.ReadFile(filepath.Join(fwDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data[:len(data)-1], &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Source != "explicit_source" {
		t.Errorf("Source = %q, want explicit_source (should not be overridden)", entry.Source)
	}
}

func TestAppendAuditZeroDurationOmitsDurationField(t *testing.T) {
	fwDir := filepath.Join(t.TempDir(), "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}
	AppendAudit(fwDir, "unblock", "1.2.3.4", "test", "cli", 0)

	data, err := os.ReadFile(filepath.Join(fwDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data[:len(data)-1], &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Duration != "" {
		t.Errorf("Duration = %q, want empty for zero duration", entry.Duration)
	}
}

func TestAppendAuditRotationDoesNotLoseNewEntry(t *testing.T) {
	fwDir := filepath.Join(t.TempDir(), "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(fwDir, "audit.jsonl")
	// Seed a file just over threshold.
	big := make([]byte, maxAuditFileSize+100)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(auditPath, big, 0600); err != nil {
		t.Fatal(err)
	}

	AppendAudit(fwDir, "block", "5.5.5.5", "after rotation", "cli", 0)

	// The old file should be at .1
	if _, err := os.Stat(auditPath + ".1"); err != nil {
		t.Errorf("rotated file missing: %v", err)
	}

	// New entry should be the only content in the fresh file.
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data[:len(data)-1], &entry); err != nil {
		t.Fatal(err)
	}
	if entry.IP != "5.5.5.5" {
		t.Errorf("new entry IP = %q after rotation", entry.IP)
	}
}

func TestAppendAuditSmallFileNoRotation(t *testing.T) {
	fwDir := filepath.Join(t.TempDir(), "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(fwDir, "audit.jsonl")
	// Write a small file under the threshold.
	if err := os.WriteFile(auditPath, []byte(`{"action":"old"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	AppendAudit(fwDir, "allow", "2.2.2.2", "test", "cli", 0)

	// No rotation should have occurred.
	if _, err := os.Stat(auditPath + ".1"); err == nil {
		t.Error("small file should not trigger rotation")
	}
}

// --- ReadAuditLog edge cases ----------------------------------------------

func TestReadAuditLogLimitLargerThanEntries(t *testing.T) {
	parent := t.TempDir()
	fwDir := filepath.Join(parent, "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}
	AppendAudit(fwDir, "block", "1.1.1.1", "test", "cli", 0)

	got := ReadAuditLog(parent, 100)
	if len(got) != 1 {
		t.Errorf("got %d entries, want 1", len(got))
	}
}

// --- resolveHost edge cases -----------------------------------------------

type failEngine struct{}

func (f *failEngine) AllowIP(ip string, reason string) error {
	return fmt.Errorf("allow denied")
}

func (f *failEngine) RemoveAllowIPBySource(ip string, source string) error {
	return nil
}

func TestDynDNSResolverResolveHostFailedLookup(t *testing.T) {
	eng := &mockEngine{}
	d := NewDynDNSResolver([]string{"this-hostname-does-not-exist.invalid"}, eng)
	d.resolveAll()
	// Should not panic, and should not add any IPs.
	if len(eng.allowed) != 0 {
		t.Errorf("failed lookup should not add IPs, got %v", eng.allowed)
	}
}

func TestDynDNSResolverResolveHostAllowFails(t *testing.T) {
	eng := &failEngine{}
	d := NewDynDNSResolver([]string{"localhost"}, eng)
	d.resolveAll()
	// AllowIP will fail, so resolved map should not include those IPs.
	d.mu.Lock()
	ips := d.resolved["localhost"]
	d.mu.Unlock()
	if len(ips) != 0 {
		t.Errorf("failed AllowIP should not add to resolved, got %v", ips)
	}
}

func TestDynDNSResolverResolveHostRemovesStaleIPs(t *testing.T) {
	eng := &mockEngine{}
	d := NewDynDNSResolver([]string{"localhost"}, eng)

	// Pre-populate with a fake IP that won't be in the DNS result.
	d.mu.Lock()
	d.resolved["localhost"] = []string{"192.0.2.99"}
	d.mu.Unlock()

	d.resolveAll()

	// 192.0.2.99 should have been removed (it's not in localhost DNS).
	found := false
	for _, ip := range eng.removed {
		if ip == "192.0.2.99" {
			found = true
			break
		}
	}
	if !found {
		t.Error("stale IP 192.0.2.99 should have been removed")
	}
}

// --- containsIP edge cases ------------------------------------------------

func TestContainsIPMissingFile(t *testing.T) {
	// containsIP with a file that doesn't exist should return false.
	if containsIP("/nonexistent/path/test.cidr", net.IP{1, 2, 3, 4}) {
		t.Error("missing file should return false")
	}
}

func TestContainsIPBadCIDRLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.cidr")
	content := "not-a-cidr\n203.0.113.0/24\nalso-invalid\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	// Should skip bad lines and still match valid ones.
	if !containsIP(path, net.IP{203, 0, 113, 5}) {
		t.Error("should match 203.0.113.5 despite invalid lines")
	}
}

func TestContainsIPNoMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.cidr")
	if err := os.WriteFile(path, []byte("10.0.0.0/8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if containsIP(path, net.IP{203, 0, 113, 5}) {
		t.Error("should not match 203.0.113.5 in 10.0.0.0/8")
	}
}

func TestContainsIPEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.cidr")
	if err := os.WriteFile(path, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	if containsIP(path, net.IP{1, 2, 3, 4}) {
		t.Error("empty file should not match any IP")
	}
}

// --- LookupIP with directory entries that are not .cidr files ------------

func TestLookupIPSkipsNonCIDRFiles(t *testing.T) {
	dir := t.TempDir()
	// Write a .cidr file and a .txt file.
	if err := os.WriteFile(filepath.Join(dir, "US.cidr"), []byte("203.0.113.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("203.0.113.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}

	matches := LookupIP(dir, "203.0.113.5")
	if len(matches) != 1 || matches[0] != "US" {
		t.Errorf("got %v, want [US] (notes.txt should be skipped)", matches)
	}
}

func TestLookupIPSkipsDirectories(t *testing.T) {
	dir := t.TempDir()
	// Create a subdirectory named "XX.cidr" (unusual but possible).
	if err := os.MkdirAll(filepath.Join(dir, "XX.cidr"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "US.cidr"), []byte("10.0.0.0/8\n"), 0600); err != nil {
		t.Fatal(err)
	}

	matches := LookupIP(dir, "10.0.0.1")
	if len(matches) != 1 || matches[0] != "US" {
		t.Errorf("got %v, want [US] (directory XX.cidr should be skipped)", matches)
	}
}

// --- LookupIP with multiple matching countries ---------------------------

func TestLookupIPMultipleCountries(t *testing.T) {
	dir := t.TempDir()
	// Same CIDR in two country files (unlikely but tests the multi-match path).
	if err := os.WriteFile(filepath.Join(dir, "AA.cidr"), []byte("203.0.113.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "BB.cidr"), []byte("203.0.113.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}

	matches := LookupIP(dir, "203.0.113.5")
	if len(matches) != 2 {
		t.Errorf("got %d matches, want 2", len(matches))
	}
}

// --- LoadState edge cases -------------------------------------------------

func TestLoadStateAllExpiredBlocksNetAllows(t *testing.T) {
	dir := t.TempDir()
	fwDir := filepath.Join(dir, "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}

	past := time.Now().Add(-1 * time.Hour)
	state := &FirewallState{
		Blocked:    []BlockedEntry{{IP: "1.1.1.1", ExpiresAt: past}},
		BlockedNet: []SubnetEntry{{CIDR: "10.0.0.0/8", ExpiresAt: past}},
		Allowed:    []AllowedEntry{{IP: "5.5.5.5", ExpiresAt: past}},
	}
	data, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(fwDir, "state.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Blocked) != 0 {
		t.Errorf("all expired blocks should be pruned, got %d", len(loaded.Blocked))
	}
	if len(loaded.BlockedNet) != 0 {
		t.Errorf("all expired subnets should be pruned, got %d", len(loaded.BlockedNet))
	}
	if len(loaded.Allowed) != 0 {
		t.Errorf("all expired allows should be pruned, got %d", len(loaded.Allowed))
	}
}

func TestLoadStatePermanentAndTemporaryMixed(t *testing.T) {
	dir := t.TempDir()
	fwDir := filepath.Join(dir, "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}

	future := time.Now().Add(24 * time.Hour)
	state := &FirewallState{
		Blocked: []BlockedEntry{
			{IP: "1.1.1.1", ExpiresAt: time.Time{}}, // permanent
			{IP: "2.2.2.2", ExpiresAt: future},      // temporary active
		},
	}
	data, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(fwDir, "state.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Blocked) != 2 {
		t.Errorf("both permanent and active temp should remain, got %d", len(loaded.Blocked))
	}
}

// --- InferProvenance: additional branches ---------------------------------

func TestInferProvenanceApplyAction(t *testing.T) {
	// "apply" action — not a system action, should be unknown.
	if got := InferProvenance("apply", "applied firewall rules"); got != SourceUnknown {
		t.Errorf("apply action = %q, want unknown", got)
	}
}

func TestInferProvenanceBlockReasonEmpty(t *testing.T) {
	// Block with empty reason and non-system action → unknown.
	if got := InferProvenance("block", ""); got != SourceUnknown {
		t.Errorf("block empty reason = %q, want unknown", got)
	}
}

func TestInferProvenancePermbblockTypo(t *testing.T) {
	// The source code has "permbblock" as well as "permblock".
	if got := InferProvenance("block", "permbblock for repeat offenses"); got != SourceAutoResponse {
		t.Errorf("permbblock = %q, want auto_response", got)
	}
}

func TestInferProvenanceBulkWhitelist(t *testing.T) {
	if got := InferProvenance("allow", "bulk whitelist from API"); got != SourceWhitelist {
		t.Errorf("bulk whitelist = %q, want whitelist", got)
	}
}

func TestInferProvenanceAllowedFromFirewallLookup(t *testing.T) {
	if got := InferProvenance("allow", "allowed from firewall lookup"); got != SourceWebUI {
		t.Errorf("allowed from firewall lookup = %q, want web_ui", got)
	}
}

func TestInferProvenanceAuthEqualsOutbound(t *testing.T) {
	// "auth=" in Received is for detectDirection, not InferProvenance.
	// InferProvenance with random reason should be unknown.
	if got := InferProvenance("allow", "auth= something"); got != SourceUnknown {
		t.Errorf("auth= = %q, want unknown", got)
	}
}

// --- DefaultConfig field validation ---------------------------------------

func TestDefaultConfigHasSMTPPorts(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.SMTPPorts) == 0 {
		t.Error("SMTPPorts should have defaults")
	}
	found25 := false
	for _, p := range cfg.SMTPPorts {
		if p == 25 {
			found25 = true
		}
	}
	if !found25 {
		t.Error("SMTPPorts should include port 25")
	}
}

func TestDefaultConfigSYNFloodProtection(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.SYNFloodProtection {
		t.Error("SYNFloodProtection should be true by default")
	}
}

func TestDefaultConfigDenyIPLimits(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.DenyIPLimit == 0 {
		t.Error("DenyIPLimit should be set")
	}
	if cfg.DenyTempIPLimit == 0 {
		t.Error("DenyTempIPLimit should be set")
	}
}

func TestDefaultConfigDropNoLog(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.DropNoLog) == 0 {
		t.Error("DropNoLog should have default ports")
	}
}

// --- LoadState: non-existent parent with permission error -----------------

func TestLoadStatePermissionError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test as root")
	}
	dir := t.TempDir()
	fwDir := filepath.Join(dir, "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(fwDir, "state.json")
	if err := os.WriteFile(stateFile, []byte(`{"blocked":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	// Make the file unreadable.
	if err := os.Chmod(stateFile, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(stateFile, 0600) })

	_, err := LoadState(dir)
	if err == nil {
		t.Error("unreadable state file should error")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("expected permission denied, got: %v", err)
	}
}
