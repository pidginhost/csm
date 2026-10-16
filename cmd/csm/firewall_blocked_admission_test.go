package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

// Operator ruling 2 (1.5c-3b): the loader the daemon injects into alert
// suppression reads the firewall state, so it counts an executed admission
// block that has no tracker entry.
func TestFirewallBlockedIPsCountsAnAdmissionBlock(t *testing.T) {
	dir := t.TempDir()
	data, err := json.Marshal(firewall.FirewallState{Blocked: []firewall.BlockedEntry{{
		IP: "203.0.113.53", Reason: "CSM auto-block: ssh_brute", Source: firewall.SourceAutoResponse,
		ActionID: "act_" + strings.Repeat("5", 32), BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(dir, "firewall"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "firewall", "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if ips := firewallBlockedIPs(dir); !ips["203.0.113.53"] {
		t.Fatalf("ips = %v; want the admission block", ips)
	}
}
