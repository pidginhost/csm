package alert

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Operator ruling 2 (1.5c-3b): an executed admission block writes no
// tracker entry, so alert suppression counts it from the firewall state.
func TestLoadBlockedIPsCountsAnAdmissionBlock(t *testing.T) {
	prev := BlockedIPsFunc
	BlockedIPsFunc = nil
	t.Cleanup(func() { BlockedIPsFunc = prev })
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "firewall"), 0o700); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour).Format(time.RFC3339)
	state := `{"blocked":[{"ip":"203.0.113.52","reason":"CSM auto-block: ssh_brute","source":"auto_response","expires_at":"` + future + `","action_id":"act_55555555555555555555555555555555"}]}`
	if err := os.WriteFile(filepath.Join(dir, "firewall", "state.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blocked_ips.json"), []byte(`{"ips":[{"ip":"198.51.100.52","expires_at":"`+future+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if ips := loadBlockedIPs(dir); !ips["203.0.113.52"] || !ips["198.51.100.52"] {
		t.Fatalf("ips = %v; want the admission block and the tracker's own", ips)
	}
}
