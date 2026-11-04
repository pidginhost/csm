//go:build linux && nftkernel

package firewall

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Inject at the link layer so fragments reach prerouting separately, without
// first traversing output conntrack and being reassembled there.
func injectIPv4Fragments(t *testing.T, protocol byte, options, fragmented, reverse bool, id uint16) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFINDEX, ifr); err != nil {
		t.Fatal(err)
	}
	target := &unix.SockaddrLinklayer{Ifindex: int(ifr.Uint32()), Protocol: binary.NativeEndian.Uint16([]byte{8, 0})}
	source, dest := []byte{192, 0, 2, 2}, []byte{192, 0, 2, 1}
	payload := make([]byte, 24)
	binary.BigEndian.PutUint16(payload[:2], 40000+id)
	binary.BigEndian.PutUint16(payload[2:4], 443)
	checksumOffset := 16
	if protocol == unix.IPPROTO_TCP {
		payload[12], payload[13] = 0x50, 2
	} else {
		binary.BigEndian.PutUint16(payload[4:6], uint16(len(payload)))
		checksumOffset = 6
	}
	pseudo := append(append(append([]byte{}, source...), dest...), 0, protocol, 0, byte(len(payload)))
	binary.BigEndian.PutUint16(payload[checksumOffset:], optionsPacketChecksum(append(pseudo, payload...)))
	starts := []int{0}
	if fragmented {
		starts = append(starts, 16)
		if reverse {
			starts[0], starts[1] = starts[1], starts[0]
		}
	}
	for _, start := range starts {
		end, frag := len(payload), uint16(start/8)
		if fragmented && start == 0 {
			end, frag = 16, 0x2000
		}
		headerLen := 20
		if options && start == 0 {
			headerLen = 24
		}
		packet := make([]byte, headerLen+end-start)
		packet[0], packet[8], packet[9] = 0x40|byte(headerLen/4), 64, protocol
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		binary.BigEndian.PutUint16(packet[4:6], id)
		binary.BigEndian.PutUint16(packet[6:8], frag)
		copy(packet[12:16], source)
		copy(packet[16:20], dest)
		if headerLen > 20 {
			copy(packet[20:24], []byte{1, 1, 1, 0}) // NOPs and EOL are not copied to later fragments.
		}
		binary.BigEndian.PutUint16(packet[10:12], optionsPacketChecksum(packet[:headerLen]))
		copy(packet[headerLen:], payload[start:end])
		if err := unix.Sendto(fd, packet, 0, target); err != nil {
			t.Fatal(err)
		}
	}
}

func optionsPacketChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

func optionsChainPackets(t *testing.T, conn *nftables.Conn, chain *nftables.Chain) uint64 {
	t.Helper()
	rules, err := conn.GetRules(chain.Table, chain)
	if err != nil {
		t.Fatal(err)
	}
	var packets uint64
	for _, rule := range rules {
		for _, ex := range rule.Exprs {
			if counter, ok := ex.(*expr.Counter); ok {
				packets += counter.Packets
			}
		}
	}
	return packets
}

// An unconditional accept in either table must not bypass the drop. The
// later chains prove that ordinary TCP and UDP with options survive and
// receive the DNAT that normally hands published ports to containers.
func TestKernelIPv4OptionsFragmentsAndAccepts(t *testing.T) {
	isolatedFirewallNamespace(t)
	kernelLoopbackUp(t)
	e, err := NewEngine(&FirewallConfig{Enabled: true, DropIPv4Options: true}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	other := e.conn.AddTable(&nftables.Table{Name: "options_test", Family: nftables.TableFamilyINet})
	addAccept := func(table *nftables.Table, name string, priority int32) *nftables.Chain {
		chain := e.conn.AddChain(&nftables.Chain{Table: table, Name: name, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(nftables.ChainPriority(priority))})
		e.conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept}}})
		return chain
	}
	addAccept(e.table, "early_accept", -330)
	before := addAccept(other, "early_accept", -320)
	after := addAccept(other, "late_accept", -300)
	natTable := e.conn.AddTable(&nftables.Table{Name: "options_nat", Family: nftables.TableFamilyIPv4})
	nat := e.conn.AddChain(&nftables.Chain{Table: natTable, Name: "prerouting", Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest})
	e.conn.AddRule(&nftables.Rule{Table: natTable, Chain: nat, Exprs: []expr.Any{
		&expr.Counter{},
		&expr.Immediate{Register: 1, Data: []byte{198, 51, 100, 1}},
		&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1},
	}})
	translated := e.conn.AddChain(&nftables.Chain{Table: natTable, Name: "translated", Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(-90)})
	e.conn.AddRule(&nftables.Rule{Table: natTable, Chain: translated, Exprs: []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{198, 51, 100, 1}},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}})
	if err := e.conn.Flush(); err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		name                         string
		protocol                     byte
		options, fragmented, reverse bool
		wantDrop                     bool
	}{
		{"plain TCP", unix.IPPROTO_TCP, false, false, false, false},
		{"TCP options", unix.IPPROTO_TCP, true, false, false, true},
		{"fragmented TCP", unix.IPPROTO_TCP, false, true, false, false},
		{"fragmented options", unix.IPPROTO_TCP, true, true, false, true},
		{"reverse fragments", unix.IPPROTO_TCP, true, true, true, true},
		{"UDP options", unix.IPPROTO_UDP, true, false, false, false},
		{"fragmented UDP options", unix.IPPROTO_UDP, true, true, true, false},
	} {
		// Stay on the locked namespace thread; t.Run would use another thread.
		first, last := optionsChainPackets(t, e.conn, before), optionsChainPackets(t, e.conn, after)
		natted, delivered := optionsChainPackets(t, e.conn, nat), optionsChainPackets(t, e.conn, translated)
		drops, _ := ipv4OptionsDrops(t, e)
		injectIPv4Fragments(t, tc.protocol, tc.options, tc.fragmented, tc.reverse, uint16(i+1))
		deadline := time.Now().Add(time.Second)
		for {
			gotDrops, _ := ipv4OptionsDrops(t, e)
			gotFirst, gotLast := optionsChainPackets(t, e.conn, before), optionsChainPackets(t, e.conn, after)
			gotNAT, gotDelivered := optionsChainPackets(t, e.conn, nat), optionsChainPackets(t, e.conn, translated)
			wantDrops, wantLast := drops, last+1
			if tc.wantDrop {
				wantDrops, wantLast = drops+1, last
			}
			passed := wantLast - last
			if gotFirst == first+1 && gotLast == wantLast && gotDrops == wantDrops && gotNAT == natted+passed && gotDelivered == delivered+passed {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: before/drop/after/NAT/translated deltas = %d/%d/%d/%d/%d, want 1/%d/%d/%d/%d", tc.name,
					gotFirst-first, gotDrops-drops, gotLast-last, gotNAT-natted, gotDelivered-delivered, wantDrops-drops, passed, passed, passed)
			}
			time.Sleep(time.Millisecond)
		}
	}
}
