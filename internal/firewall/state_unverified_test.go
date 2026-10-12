package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// An unverified row is held for recovery and never restored to the kernel,
// so no reader of the state file reports it as a block, expired or not.
func TestLoadStateLeavesOutUnverifiedRows(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	state := FirewallState{Blocked: []BlockedEntry{
		{IP: "192.0.2.60", ExpiresAt: now.Add(time.Hour)},
		{IP: "192.0.2.61", ExpiresAt: now.Add(time.Hour), ActionID: "act_held", Unverified: true},
		{IP: "192.0.2.62", ExpiresAt: now.Add(-time.Hour), ActionID: "act_expired", Unverified: true},
		{IP: "192.0.2.63", ActionID: "act_applied"},
	}}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(dir, "firewall"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "firewall", "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, row := range loaded.Blocked {
		got = append(got, row.IP)
	}
	if len(got) != 2 || got[0] != "192.0.2.60" || got[1] != "192.0.2.63" {
		t.Fatalf("loaded blocks = %v; want only the enforced rows", got)
	}
}
