package threat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

// Operator ruling 2 (1.5c-3b): a threat lookup reports an executed
// admission block from the firewall state, though the tracker never named
// the address.
func TestLookupReportsAnAdmissionBlock(t *testing.T) {
	dir := t.TempDir()
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	data, err := json.Marshal(firewall.FirewallState{Blocked: []firewall.BlockedEntry{{
		IP: "203.0.113.54", Reason: "CSM auto-block: ssh_brute", Source: firewall.SourceAutoResponse,
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
	if err = os.WriteFile(filepath.Join(dir, "blocked_ips.json"), []byte(`{"ips":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	intel := Lookup("203.0.113.54", dir)
	if intel == nil || !intel.CurrentlyBlocked || intel.BlockReason != "CSM auto-block: ssh_brute" || intel.BlockExpiresAt == nil || !intel.BlockExpiresAt.Equal(expires) {
		t.Fatalf("lookup = %+v; want the admission block", intel)
	}
}
