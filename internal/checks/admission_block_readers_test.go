package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// writeAdmissionBlock writes the firewall state an executed admission
// block leaves: a verified row naming its action, with no tracker entry.
// The legacy tracker names another address only.
func writeAdmissionBlock(t *testing.T, dir, ip string, expires time.Time) {
	t.Helper()
	data, err := json.Marshal(firewall.FirewallState{Blocked: []firewall.BlockedEntry{{
		IP: ip, Reason: "CSM auto-block: ssh_brute", Source: firewall.SourceAutoResponse,
		ActionID: "act_" + strings.Repeat("5", 32), BlockedAt: time.Now(), ExpiresAt: expires,
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
	tracker := `{"ips":[{"ip":"198.51.100.50","expires_at":"` + expires.Format(time.RFC3339) + `"}]}`
	if err = os.WriteFile(filepath.Join(dir, blockStateFile), []byte(tracker), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Operator ruling 2 (1.5c-3b): an executed admission block writes no
// tracker entry, so reputation must count it from the firewall state.
func TestLoadAllBlockedIPsCountsAnAdmissionBlock(t *testing.T) {
	dir := t.TempDir()
	writeAdmissionBlock(t, dir, "203.0.113.50", time.Now().Add(time.Hour))
	if blocked := loadAllBlockedIPs(dir); !blocked["203.0.113.50"] || !blocked["198.51.100.50"] {
		t.Fatalf("blocked = %v; want the admission block and the tracker's own", blocked)
	}
}

// A flush removes the threat row an admission block's consumer recorded,
// though the tracker never named the address.
func TestFlushAutoBlockStateClearsAnAdmissionBlockThreatRow(t *testing.T) {
	withTestThreatStore(t)
	dir := t.TempDir()
	restore := SetGlobalThreatDBForTest(dir)
	t.Cleanup(restore)
	expires := time.Now().Add(time.Hour)
	writeAdmissionBlock(t, dir, "203.0.113.51", expires)
	if err := GetThreatDB().AddTemporaryUntil("203.0.113.51", "CSM auto-block: ssh_brute", expires); err != nil {
		t.Fatal(err)
	}
	if _, err := FlushAutoBlockState(dir, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if match, ok := GetThreatDB().LookupMatch("203.0.113.51"); ok {
		t.Fatalf("flush kept the admission block's threat row: %+v", match)
	}
	if _, found := store.Global().GetPermanentBlock("203.0.113.51"); found {
		t.Fatal("flush kept the admission block's stored threat row")
	}
}
