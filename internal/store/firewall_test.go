package store

import (
	"testing"
	"time"
)

func TestFirewallBlockUnblock(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Block an IP (permanent — zero expiry).
	if err := db.BlockIP("10.0.0.1", "brute-force", time.Time{}); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}

	// Verify it's returned by GetBlockedIP.
	entry, found := db.GetBlockedIP("10.0.0.1")
	if !found {
		t.Fatal("GetBlockedIP(10.0.0.1): not found")
	}
	if entry.IP != "10.0.0.1" {
		t.Fatalf("IP = %q, want %q", entry.IP, "10.0.0.1")
	}
	if entry.Reason != "brute-force" {
		t.Fatalf("Reason = %q, want %q", entry.Reason, "brute-force")
	}

	// Unblock it.
	if err := db.UnblockIP("10.0.0.1"); err != nil {
		t.Fatalf("UnblockIP: %v", err)
	}

	// Verify it's gone.
	_, found = db.GetBlockedIP("10.0.0.1")
	if found {
		t.Fatal("GetBlockedIP(10.0.0.1) should not be found after unblock")
	}
}

func TestFirewallPortAllows(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Add 3 port allows for the same IP.
	if err := db.AddPortAllow("10.0.0.2", 443, "tcp", "HTTPS"); err != nil {
		t.Fatalf("AddPortAllow(443/tcp): %v", err)
	}
	if err := db.AddPortAllow("10.0.0.2", 8080, "tcp", "alt-HTTP"); err != nil {
		t.Fatalf("AddPortAllow(8080/tcp): %v", err)
	}
	if err := db.AddPortAllow("10.0.0.2", 53, "udp", "DNS"); err != nil {
		t.Fatalf("AddPortAllow(53/udp): %v", err)
	}

	// List and verify count.
	entries := db.ListPortAllows()
	if len(entries) != 3 {
		t.Fatalf("ListPortAllows len = %d, want 3", len(entries))
	}

	// Verify distinct composite keys.
	keys := make(map[string]bool)
	for _, e := range entries {
		keys[e.Key] = true
	}

	expectedKeys := []string{
		"10.0.0.2:443/tcp",
		"10.0.0.2:8080/tcp",
		"10.0.0.2:53/udp",
	}
	for _, k := range expectedKeys {
		if !keys[k] {
			t.Fatalf("missing expected key %q in ListPortAllows", k)
		}
	}
}

func TestFirewallLoadState(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now()

	// 2 blocked IPs (1 permanent, 1 future expiry) + 1 expired.
	if err := db.BlockIP("10.0.0.1", "scan", time.Time{}); err != nil {
		t.Fatalf("BlockIP(10.0.0.1): %v", err)
	}
	if err := db.BlockIP("10.0.0.2", "brute", now.Add(1*time.Hour)); err != nil {
		t.Fatalf("BlockIP(10.0.0.2): %v", err)
	}
	if err := db.BlockIP("10.0.0.3", "expired-attack", now.Add(-1*time.Hour)); err != nil {
		t.Fatalf("BlockIP(10.0.0.3): %v", err)
	}

	// 1 allowed IP.
	if err := db.AllowIP("192.168.1.1", "trusted", time.Time{}); err != nil {
		t.Fatalf("AllowIP: %v", err)
	}

	// 1 subnet.
	if err := db.AddSubnet("10.10.0.0/16", "office"); err != nil {
		t.Fatalf("AddSubnet: %v", err)
	}

	// 1 port allow.
	if err := db.AddPortAllow("172.16.0.1", 443, "tcp", "HTTPS"); err != nil {
		t.Fatalf("AddPortAllow: %v", err)
	}

	// Load full state.
	state := db.LoadFirewallState()

	// Blocked: 2 (expired one filtered out).
	if len(state.Blocked) != 2 {
		t.Fatalf("Blocked len = %d, want 2", len(state.Blocked))
	}
	blockedIPs := make(map[string]bool)
	for _, b := range state.Blocked {
		blockedIPs[b.IP] = true
	}
	if blockedIPs["10.0.0.3"] {
		t.Fatal("expired IP 10.0.0.3 should not appear in Blocked")
	}
	if !blockedIPs["10.0.0.1"] || !blockedIPs["10.0.0.2"] {
		t.Fatal("non-expired blocked IPs should be present")
	}

	// Allowed: 1.
	if len(state.Allowed) != 1 {
		t.Fatalf("Allowed len = %d, want 1", len(state.Allowed))
	}
	if state.Allowed[0].IP != "192.168.1.1" {
		t.Fatalf("Allowed[0].IP = %q, want %q", state.Allowed[0].IP, "192.168.1.1")
	}

	// Subnets: 1.
	if len(state.Subnets) != 1 {
		t.Fatalf("Subnets len = %d, want 1", len(state.Subnets))
	}
	if state.Subnets[0].CIDR != "10.10.0.0/16" {
		t.Fatalf("Subnets[0].CIDR = %q, want %q", state.Subnets[0].CIDR, "10.10.0.0/16")
	}

	// PortAllowed: 1.
	if len(state.PortAllowed) != 1 {
		t.Fatalf("PortAllowed len = %d, want 1", len(state.PortAllowed))
	}
	if state.PortAllowed[0].Key != "172.16.0.1:443/tcp" {
		t.Fatalf("PortAllowed[0].Key = %q, want %q", state.PortAllowed[0].Key, "172.16.0.1:443/tcp")
	}
}
