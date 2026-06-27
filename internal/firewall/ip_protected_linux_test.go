//go:build linux

package firewall

import (
	"errors"
	"testing"
)

// TestBlockIPProtectedErrorSentinel verifies that refusals for the host's own
// interface addresses and operator infra_ips wrap ErrIPProtected, so
// auto-response callers can treat them as an expected no-op (no record, no
// failure log) rather than a block error. The refusal still happens; only its
// classification changes.
func TestBlockIPProtectedErrorSentinel(t *testing.T) {
	tests := []struct {
		name       string
		cfg        FirewallConfig
		ip         string
		localAddrs []string
		setup      func(*Engine)
		want       string
	}{
		{
			name: "own host",
			cfg:  FirewallConfig{Enabled: true},
			ip:   "192.0.2.10",
			localAddrs: []string{
				"192.0.2.10",
			},
			want: "refusing to block local host IP: 192.0.2.10 (own interface address)",
		},
		{
			name: "static infra ip",
			cfg:  FirewallConfig{Enabled: true, InfraIPs: []string{"203.0.113.5"}},
			ip:   "203.0.113.5",
			want: "refusing to block infra IP: 203.0.113.5",
		},
		{
			name: "infra cidr",
			cfg:  FirewallConfig{Enabled: true, InfraIPs: []string{"203.0.113.0/24"}},
			ip:   "203.0.113.77",
			want: "refusing to block infra IP: 203.0.113.77 (in 203.0.113.0/24)",
		},
		{
			name: "resolved infra host",
			cfg:  FirewallConfig{Enabled: true, InfraIPs: []string{"panel.example"}},
			ip:   "198.51.100.9",
			setup: func(e *Engine) {
				e.UpdateInfraResolved("panel.example", []string{"198.51.100.9"})
			},
			want: "refusing to block infra IP: 198.51.100.9 (resolved from panel.example)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			e := &Engine{
				cfg:           &cfg,
				statePath:     t.TempDir(),
				dryRunEnabled: func() bool { return false },
				localAddrsLookup: func() ([]string, error) {
					return tt.localAddrs, nil
				},
			}
			if tt.setup != nil {
				tt.setup(e)
			}
			err := e.BlockIP(tt.ip, "test", 0)
			if !errors.Is(err, ErrIPProtected) {
				t.Fatalf("BlockIP(%q): want errors.Is(err, ErrIPProtected), got %v", tt.ip, err)
			}
			if err.Error() != tt.want {
				t.Fatalf("BlockIP(%q) error = %q, want %q", tt.ip, err.Error(), tt.want)
			}
		})
	}
}
