package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFirewallBlockedIPsSkipsUnverifiedRows(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "firewall"), 0700); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour).Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).Format(time.RFC3339)
	data := `{"blocked":[
		{"ip":"203.0.113.1","expires_at":"` + future + `"},
		{"ip":"203.0.113.3","expires_at":"` + past + `","action_id":"act_unknown","unverified":true},
		{"ip":"203.0.113.4","expires_at":"` + future + `","action_id":"act_running","unverified":true}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "firewall", "state.json"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	ips := firewallBlockedIPs(dir)
	if len(ips) != 1 || !ips["203.0.113.1"] {
		t.Fatalf("ips = %v; unverified rows must not suppress alerts", ips)
	}
}
