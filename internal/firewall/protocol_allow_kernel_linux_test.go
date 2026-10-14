//go:build linux && nftkernel

package firewall

import (
	"testing"

	"github.com/google/nftables"
)

func kernelChainRuleCount(t *testing.T, e *Engine, chain *nftables.Chain) int {
	t.Helper()
	rules, err := e.conn.GetRules(e.table, chain)
	if err != nil {
		t.Fatal(err)
	}
	return len(rules)
}

// The kernel must accept the peer and group rules for both families, and a
// reload without the key must take them out again.
func TestKernelProtocolAllowAppliesAndReloads(t *testing.T) {
	isolatedFirewallNamespace(t)
	without := &FirewallConfig{Enabled: true, IPv6: true, TCPOut: []int{443}}
	e, err := NewEngine(without, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	baseIn, baseOut := kernelChainRuleCount(t, e, e.chainIn), kernelChainRuleCount(t, e, e.chainOut)

	with := *without
	with.ProtocolAllow = []ProtocolAllowRule{{Protocol: "vrrp", Peers: []string{"192.0.2.11", "2001:db8::/64"}}}
	e.SetConfig(&with)
	if err := e.Apply(); err != nil {
		t.Fatalf("kernel refused the protocol_allow rules: %v", err)
	}
	if in, out := kernelChainRuleCount(t, e, e.chainIn), kernelChainRuleCount(t, e, e.chainOut); in != baseIn+2 || out != baseOut+4 {
		t.Fatalf("input %d output %d rules, want %d and %d (two peers in, two peers and two groups out)", in, out, baseIn+2, baseOut+4)
	}

	e.SetConfig(without)
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if in, out := kernelChainRuleCount(t, e, e.chainIn), kernelChainRuleCount(t, e, e.chainOut); in != baseIn || out != baseOut {
		t.Fatalf("rollback left input %d output %d rules, want %d and %d", in, out, baseIn, baseOut)
	}
}
