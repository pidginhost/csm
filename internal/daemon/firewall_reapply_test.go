package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// `csm firewall restart` and `apply-confirmed` re-applied the FirewallConfig
// copy taken at daemon start, so an edited firewall block was reported as
// applied while nothing changed, and then took effect unprotected at the
// next daemon restart. The re-apply commands read the firewall block from
// csm.yaml on disk.
func TestLoadEffectiveFirewallFromDiskReadsEditedBlock(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")
	body := "hostname: host.example\nstate_path: " + dir + "\nfirewall:\n  enabled: true\n  tcp_in: [22, 80, 443, 8443]\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	effective, err := loadEffectiveFirewallFromDisk(cfgPath, "")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if effective == nil || !effective.Enabled {
		t.Fatalf("effective firewall = %+v, want enabled", effective)
	}
	var has8443 bool
	for _, p := range effective.TCPIn {
		if p == 8443 {
			has8443 = true
		}
	}
	if !has8443 {
		t.Fatalf("edited tcp_in not read from disk: %v", effective.TCPIn)
	}
}
