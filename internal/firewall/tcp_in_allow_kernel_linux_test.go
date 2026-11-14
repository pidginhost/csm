//go:build linux && nftkernel

package firewall

import (
	"net"
	"testing"
)

// Exercise the kernel's verdicts on a port tcp_in leaves closed: a listed
// source that is blocked still reaches that port and nothing else, and an
// unlisted source does not reach it at all.
func TestKernelInAllowBlockedSourceReachesOnlyItsPort(t *testing.T) {
	isolatedFirewallNamespace(t)
	kernelLoopbackUp(t)

	sources := []string{"192.0.2.11", "2001:db8::11"}
	cfg := &FirewallConfig{Enabled: true, IPv6: true, UDPIn: []int{53}, TCPOut: []int{443},
		TCPInAllow: inAllow(443, sources...)}
	e, err := NewEngine(cfg, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Apply(); err != nil {
		t.Fatalf("kernel refused the tcp_in_allow rules: %v", err)
	}
	for _, source := range sources {
		if err = e.BlockIPForce(source, "test", 0); err != nil {
			t.Fatal(err)
		}
	}
	instrumentProtocolInput(t, e)

	// sendProtocolPacket aims TCP at port 443 and UDP at port 53.
	for _, tc := range []struct {
		name   string
		source string
		proto  byte
		want   [3]uint64 // accepts, drops, blocklist drops
	}{
		{"listed ipv4 on its port", "192.0.2.11", 6, [3]uint64{1, 0, 0}},
		{"listed ipv6 on its port", "2001:db8::11", 6, [3]uint64{1, 0, 0}},
		{"listed ipv4 on an open udp port", "192.0.2.11", 17, [3]uint64{0, 1, 1}},
		{"listed ipv6 on an open udp port", "2001:db8::11", 17, [3]uint64{0, 1, 1}},
		{"unlisted ipv4", "192.0.2.12", 6, [3]uint64{0, 1, 0}},
		{"unlisted ipv6", "2001:db8::12", 6, [3]uint64{0, 1, 0}},
	} {
		before := protocolInputCounters(t, e)
		sendProtocolPacket(t, net.ParseIP(tc.source), tc.proto)
		after := awaitProtocolInput(t, e, before)
		got := [3]uint64{after[0] - before[0], after[1] - before[1], after[2] - before[2]}
		if got != tc.want {
			t.Errorf("%s: accepts/drops/blocklist drops=%v, want %v", tc.name, got, tc.want)
		}
	}
}
