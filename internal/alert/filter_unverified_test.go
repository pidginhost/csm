package alert

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
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

func TestUnverifiedFirewallRowsOverrideLegacyBlocks(t *testing.T) {
	for _, injected := range []bool{false, true} {
		name := "fallback"
		if injected {
			name = "injected"
		}
		t.Run(name, func(t *testing.T) {
			prev := BlockedIPsFunc
			BlockedIPsFunc = nil
			if injected {
				BlockedIPsFunc = func() map[string]bool { return map[string]bool{"203.0.113.1": true} }
			}
			t.Cleanup(func() { BlockedIPsFunc = prev })
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "firewall"), 0o700); err != nil {
				t.Fatal(err)
			}
			data := `{"blocked":[
				{"ip":"203.0.113.1"},
				{"ip":"203.0.113.3","expires_at":"2099-01-01T00:00:00Z","unverified":true},
				{"ip":"203.0.113.4","expires_at":"2000-01-01T00:00:00Z","unverified":true},
				{"ip":"203.0.113.5","unverified":true},
				{"ip":"2001:db8::3","unverified":true}
			]}`
			if err := os.WriteFile(filepath.Join(dir, "firewall", "state.json"), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			legacy := `{"ips":[
				{"ip":"203.0.113.2"},
				{"ip":"::ffff:203.0.113.3"},
				{"ip":"203.0.113.4"},
				{"ip":"203.0.113.5"},
				{"ip":"2001:db8:0:0:0:0:0:3"}
			]}`
			if err := os.WriteFile(filepath.Join(dir, "blocked_ips.json"), []byte(legacy), 0o600); err != nil {
				t.Fatal(err)
			}
			ips := loadBlockedIPs(dir)
			if len(ips) != 2 || !ips["203.0.113.1"] || !ips["203.0.113.2"] {
				t.Fatalf("blocks = %v; legacy rows must not override unverified state", ips)
			}
			cfg := &config.Config{StatePath: dir}
			cfg.Suppressions.SuppressBlockedAlerts = true
			var findings []Finding
			for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5", "2001:db8::3"} {
				findings = append(findings, Finding{Check: "ip_reputation", SourceIP: ip, Severity: Critical})
			}
			got := FilterBlockedAlerts(cfg, findings)
			if len(got) != 4 {
				t.Fatalf("kept %d alerts; want every unverified address visible", len(got))
			}
			for i, finding := range got {
				if finding.SourceIP != findings[i+2].SourceIP {
					t.Fatalf("kept alert %d for %s, want %s", i, finding.SourceIP, findings[i+2].SourceIP)
				}
			}
		})
	}
}
