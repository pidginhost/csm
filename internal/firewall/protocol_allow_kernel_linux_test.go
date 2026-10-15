//go:build linux && nftkernel

package firewall

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func kernelChainRuleCount(t *testing.T, e *Engine, chain *nftables.Chain) int {
	t.Helper()
	rules, err := e.conn.GetRules(e.table, chain)
	if err != nil {
		t.Fatal(err)
	}
	return len(rules)
}

// Exercise the kernel's verdicts, including the negative case: a peer gets
// no exception for TCP, UDP, ICMP or another portless protocol.
func TestKernelProtocolAllowBlockedPeerTraffic(t *testing.T) {
	isolatedFirewallNamespace(t)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		t.Fatal(err)
	}
	ifr.SetUint16(unix.IFF_UP)
	if err = unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		t.Fatal(err)
	}

	cfg := &FirewallConfig{Enabled: true, IPv6: true, TCPIn: []int{443}, UDPIn: []int{53}, TCPOut: []int{443},
		ProtocolAllow: vrrpPeers("192.0.2.11", "2001:db8::11")}
	stateDir := t.TempDir()
	e, err := NewEngine(cfg, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Apply(); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []string{"192.0.2.11", "2001:db8::11"} {
		if err = e.BlockIPForce(peer, "test", 0); err != nil {
			t.Fatal(err)
		}
	}

	for _, restart := range []bool{false, true} {
		if restart {
			// A reboot loses the kernel table, then a fresh engine restores
			// persisted blocks and the configured protocol exceptions together.
			e.conn.DelTable(e.table)
			if err = e.conn.Flush(); err != nil {
				t.Fatal(err)
			}
			e, err = NewEngine(cfg, stateDir)
			if err != nil {
				t.Fatal(err)
			}
			if err = e.Apply(); err != nil {
				t.Fatal(err)
			}
		}
		instrumentProtocolInput(t, e)
		for _, peer := range []string{"192.0.2.11", "2001:db8::11"} {
			for _, proto := range []byte{112, 6, 17, 47, icmpProtocol(net.ParseIP(peer))} {
				before := protocolInputCounters(t, e)
				sendProtocolPacket(t, net.ParseIP(peer), proto)
				after := awaitProtocolInput(t, e, before)
				want := [3]uint64{0, 1, 1}
				if proto == 112 {
					want = [3]uint64{1, 0, 0}
				}
				got := [3]uint64{after[0] - before[0], after[1] - before[1], after[2] - before[2]}
				if got != want {
					t.Fatalf("restart=%t peer=%s proto=%d: accepts/drops/blocklist drops=%v, want %v", restart, peer, proto, got, want)
				}
			}
		}
		for _, stranger := range []string{"192.0.2.12", "2001:db8::12"} {
			before := protocolInputCounters(t, e)
			sendProtocolPacket(t, net.ParseIP(stranger), 112)
			after := awaitProtocolInput(t, e, before)
			if after[0] != before[0] || after[1] != before[1]+1 {
				t.Fatalf("restart=%t: unlisted source %s was not dropped", restart, stranger)
			}
		}
	}
}

func instrumentProtocolInput(t *testing.T, e *Engine) {
	t.Helper()
	rules, err := e.conn.GetRules(e.table, e.chainIn)
	if err != nil {
		t.Fatal(err)
	}
	// Locally injected packets must traverse the peer/block rules instead
	// of the normal loopback exemption. Keep every other rule and its order.
	loopback := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("lo\x00")},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
	if len(rules) == 0 || !reflect.DeepEqual(rules[0].Exprs, loopback) {
		t.Fatal("first input rule is not the loopback exemption")
	}
	e.conn.FlushChain(e.chainIn)
	for _, rule := range rules[1:] {
		last := len(rule.Exprs) - 1
		if _, ok := rule.Exprs[last].(*expr.Verdict); ok {
			rule.Exprs = append(rule.Exprs[:last], &expr.Counter{}, rule.Exprs[last])
		}
		rule.Handle, rule.Position = 0, 0
		e.conn.AddRule(rule)
	}
	e.conn.AddRule(&nftables.Rule{Table: e.table, Chain: e.chainIn, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}})
	if err = e.conn.Flush(); err != nil {
		t.Fatal(err)
	}
}

func protocolInputCounters(t *testing.T, e *Engine) [3]uint64 {
	t.Helper()
	rules, err := e.conn.GetRules(e.table, e.chainIn)
	if err != nil {
		t.Fatal(err)
	}
	var counts [3]uint64
	for _, rule := range rules {
		verdict, ok := rule.Exprs[len(rule.Exprs)-1].(*expr.Verdict)
		if !ok {
			continue
		}
		blocked := false
		for _, ex := range rule.Exprs {
			if lookup, ok := ex.(*expr.Lookup); ok && (lookup.SetName == e.setBlocked.Name || lookup.SetName == e.setBlocked6.Name) {
				blocked = true
			}
		}
		for _, ex := range rule.Exprs {
			if counter, ok := ex.(*expr.Counter); ok {
				switch verdict.Kind {
				case expr.VerdictAccept:
					counts[0] += counter.Packets
				case expr.VerdictDrop:
					counts[1] += counter.Packets
					if blocked {
						counts[2] += counter.Packets
					}
				}
			}
		}
	}
	return counts
}

func awaitProtocolInput(t *testing.T, e *Engine, before [3]uint64) [3]uint64 {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		after := protocolInputCounters(t, e)
		if after[0]+after[1] > before[0]+before[1] {
			return after
		}
		if time.Now().After(deadline) {
			t.Fatal("injected packet did not reach the input chain")
		}
		time.Sleep(time.Millisecond)
	}
}

func sendProtocolPacket(t *testing.T, source net.IP, proto byte) {
	t.Helper()
	family, level, option := unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL
	dest := net.IPv6loopback
	var target unix.Sockaddr = &unix.SockaddrInet6{Addr: [16]byte(net.IPv6loopback.To16())}
	packet := make([]byte, 40+20)
	packet[0], packet[6], packet[7] = 0x60, proto, 255
	binary.BigEndian.PutUint16(packet[4:6], 20)
	copy(packet[8:24], source.To16())
	copy(packet[24:40], dest.To16())
	if source.To4() != nil {
		family, level, option = unix.AF_INET, unix.IPPROTO_IP, unix.IP_HDRINCL
		dest = net.IPv4(127, 0, 0, 1).To4()
		target = &unix.SockaddrInet4{Addr: [4]byte(dest)}
		packet = make([]byte, 20+20)
		packet[0], packet[8], packet[9] = 0x45, 255, proto
		binary.BigEndian.PutUint16(packet[2:4], 40)
		copy(packet[12:16], source.To4())
		copy(packet[16:20], dest)
	}
	payload := packet[len(packet)-20:]
	checksumOffset := -1
	switch proto {
	case 6:
		binary.BigEndian.PutUint16(payload[:2], 40000)
		binary.BigEndian.PutUint16(payload[2:4], 443)
		payload[12], payload[13] = 0x50, 2 // TCP SYN, no options.
		checksumOffset = 16
	case 17:
		binary.BigEndian.PutUint16(payload[:2], 40000)
		binary.BigEndian.PutUint16(payload[2:4], 53)
		binary.BigEndian.PutUint16(payload[4:6], 20)
		checksumOffset = 6
	case 1:
		payload[0] = 8
		checksumOffset = 2
	case 58:
		payload[0] = 128
		checksumOffset = 2
	}
	if checksumOffset >= 0 {
		var pseudo []byte
		if proto != 1 {
			if family == unix.AF_INET {
				pseudo = append(pseudo, source.To4()...)
				pseudo = append(pseudo, dest.To4()...)
				pseudo = append(pseudo, 0, proto, 0, 20)
			} else {
				pseudo = append(pseudo, source.To16()...)
				pseudo = append(pseudo, dest.To16()...)
				pseudo = append(pseudo, 0, 0, 0, 20, 0, 0, 0, proto)
			}
		}
		pseudo = append(pseudo, payload...)
		var sum uint32
		for i := 0; i < len(pseudo); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(pseudo[i:]))
		}
		for sum > 0xffff {
			sum = sum>>16 + sum&0xffff
		}
		binary.BigEndian.PutUint16(payload[checksumOffset:], ^uint16(sum))
	}
	fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.SetsockoptInt(fd, level, option, 1); err != nil {
		t.Fatal(err)
	}
	if err := unix.Sendto(fd, packet, 0, target); err != nil {
		t.Fatal(err)
	}
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

func icmpProtocol(ip net.IP) byte {
	if ip.To4() != nil {
		return 1
	}
	return 58
}
