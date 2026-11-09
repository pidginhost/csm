//go:build linux

package firewall

import "testing"

// BlockProtected answers the same question the block path asks, so a
// caller about to act on an address can skip what no block may name.
func TestEngineBlockProtected(t *testing.T) {
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true, InfraIPs: []string{"203.0.113.0/28", "198.51.100.20"}},
		statePath:     t.TempDir(),
		dryRunEnabled: func() bool { return false },
	}
	e.UpdateInfraResolved("panel.example.net", []string{"198.51.100.5"})

	for _, ip := range []string{"203.0.113.5", "198.51.100.20", "198.51.100.5", "::ffff:198.51.100.5", "127.0.0.1", "::1", "fe80::1"} {
		if !e.BlockProtected(ip) {
			t.Errorf("BlockProtected(%q) = false, want true", ip)
		}
	}
	for _, ip := range []string{"192.0.2.44", "2001:db8::44", "not-an-ip", ""} {
		if e.BlockProtected(ip) {
			t.Errorf("BlockProtected(%q) = true, want false", ip)
		}
	}
}
