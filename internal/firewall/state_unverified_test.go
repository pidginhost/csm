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

// The engine gives an unverified duplicate precedence over every alias of
// the same address, including when that recovery row has already expired.
func TestLoadStateLeavesOutAliasesOfUnverifiedRows(t *testing.T) {
	for _, pair := range [][2]string{
		{"192.0.2.64", "::ffff:192.0.2.64"},
		{"2001:db8::64", "2001:0db8:0:0:0:0:0:64"},
	} {
		for _, expired := range []bool{false, true} {
			for _, reverse := range []bool{false, true} {
				dir := t.TempDir()
				expires := time.Now().Add(time.Hour)
				if expired {
					expires = time.Now().Add(-time.Hour)
				}
				rows := []BlockedEntry{
					{IP: pair[0], ActionID: "act_held", Unverified: true, ExpiresAt: expires},
					{IP: pair[1], Reason: "operator"},
					{IP: "198.51.100.64", Reason: "operator"},
				}
				if reverse {
					rows[0], rows[1] = rows[1], rows[0]
				}
				data, err := json.Marshal(FirewallState{Blocked: rows})
				if err != nil {
					t.Fatal(err)
				}
				if err = os.MkdirAll(filepath.Join(dir, "firewall"), 0o700); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, "firewall", "state.json")
				if err = os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				loaded, err := LoadState(dir)
				if err != nil {
					t.Fatal(err)
				}
				if len(loaded.Blocked) != 1 || loaded.Blocked[0].IP != "198.51.100.64" {
					t.Errorf("aliases %v, expired=%v, reverse=%v: loaded %+v; want only the unrelated block", pair, expired, reverse, loaded.Blocked)
				}
				if after, err := os.ReadFile(path); err != nil || string(after) != string(data) {
					t.Fatalf("display changed recovery state: %v", err)
				}
			}
		}
	}
}
