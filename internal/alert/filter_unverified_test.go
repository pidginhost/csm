package alert

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadBlockedIPsSkipsUnverifiedFirewallRows(t *testing.T) {
	prev := BlockedIPsFunc
	BlockedIPsFunc = nil
	t.Cleanup(func() { BlockedIPsFunc = prev })
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "firewall"), 0700); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour).Format(time.RFC3339)
	data := `{"blocked":[
		{"ip":"203.0.113.1","expires_at":"` + future + `"},
		{"ip":"203.0.113.3","expires_at":"` + future + `","action_id":"act_unknown","unverified":true}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "firewall", "state.json"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	ips := loadBlockedIPs(dir)
	if !ips["203.0.113.1"] || ips["203.0.113.3"] {
		t.Fatalf("ips = %v; an unverified row must not suppress alerts", ips)
	}
}
