//go:build linux

package firewall

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// capturedMessage flushes what build queues into a fresh csm table and
// returns the first message of msgType, for byte comparison with an Apply.
func capturedMessage(t *testing.T, msgType int, build func(*nftables.Conn, *nftables.Table)) []byte {
	t.Helper()
	conn, captured := nftConnCapturingRules(t)
	build(conn, conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet}))
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	want := netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | msgType)
	for _, msg := range *captured {
		if msg.Header.Type == want {
			return append([]byte(nil), msg.Data...)
		}
	}
	t.Fatalf("captured batch has no message of type %d", msgType)
	return nil
}

// Unpatched kernels race on the IP options a connection request carries
// (CVE-2026-98432). The drop has its own prerouting chain so it runs before
// conntrack, NAT to containers and every accept, infra included.
func TestApplyDropsIPv4TCPOptionsBeforeEveryAccept(t *testing.T) {
	accept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Name:     "prerouting",
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(-310),
		Policy:   &accept,
	}
	wantChain := capturedMessage(t, unix.NFT_MSG_NEWCHAIN, func(conn *nftables.Conn, table *nftables.Table) {
		chain.Table = table
		conn.AddChain(chain)
	})
	wantRule := capturedMessage(t, unix.NFT_MSG_NEWRULE, func(conn *nftables.Conn, table *nftables.Table) {
		chain.Table = table
		conn.AddRule(&nftables.Rule{Table: table, Chain: conn.AddChain(chain), Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x0f}, Xor: []byte{0}},
			&expr.Cmp{Op: expr.CmpOpGt, Register: 1, Data: []byte{5}},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		}})
	})

	for _, on := range []bool{true, false} {
		conn, captured := nftConnCapturingRules(t)
		e := &Engine{conn: conn, cfg: &FirewallConfig{TCPOut: []int{443}, DropIPv4Options: on}, statePath: t.TempDir(),
			listTables: func() ([]*nftables.Table, error) { return nil, nil }}
		if err := e.Apply(); err != nil {
			t.Fatal(err)
		}
		gotChain := outputRuleIndex(*captured, wantChain) >= 0
		gotRule := outputRuleIndex(*captured, wantRule) >= 0
		if gotChain != on || gotRule != on {
			t.Errorf("drop_ipv4_options=%t: prerouting chain=%t drop rule=%t", on, gotChain, gotRule)
		}
	}
}
