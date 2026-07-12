//go:build linux

package firewall

import (
	"bytes"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
)

func captureOutputRuleData(t *testing.T, exprs []expr.Any) []byte {
	t.Helper()
	conn, captured := nftConnCapturingRules(t)
	table := conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})
	chain := conn.AddChain(&nftables.Chain{Name: "output", Table: table})
	conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	for _, msg := range *captured {
		if bytes.Contains(msg.Data, []byte("immediate\x00")) {
			return append([]byte(nil), msg.Data...)
		}
	}
	t.Fatal("captured batch has no rule message")
	return nil
}

func smtpDropRuleExprsForTest(port int) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(port))},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

func outputRuleIndex(msgs []netlink.Message, data []byte) int {
	for i, msg := range msgs {
		if bytes.Equal(msg.Data, data) {
			return i
		}
	}
	return -1
}

func TestOutputFamilyBypassesPreserveSMTPPrecedence(t *testing.T) {
	const smtpPort = 25
	smtpDrop := captureOutputRuleData(t, smtpDropRuleExprsForTest(smtpPort))
	v4Bypass := captureOutputRuleData(t, familyBypassRuleExprs(2))
	v6Bypass := captureOutputRuleData(t, familyBypassRuleExprs(10))

	for _, tc := range []struct {
		name         string
		cfg          *FirewallConfig
		bypass       []byte
		bypassBefore bool
	}{
		{
			name: "managed IPv6 bypasses IPv4 after SMTP drop",
			cfg: &FirewallConfig{
				IPv6: true, TCP6Out: []int{443}, SMTPBlock: true, SMTPPorts: []int{smtpPort},
			},
			bypass: v4Bypass,
		},
		{
			name: "unmanaged IPv6 bypasses before SMTP drop",
			cfg: &FirewallConfig{
				TCPOut: []int{443}, SMTPBlock: true, SMTPPorts: []int{smtpPort},
			},
			bypass:       v6Bypass,
			bypassBefore: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, captured := nftConnCapturingRules(t)
			e := &Engine{cfg: tc.cfg, conn: conn}
			e.table = conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})
			if err := e.createOutputChain(); err != nil {
				t.Fatal(err)
			}
			if err := conn.Flush(); err != nil {
				t.Fatal(err)
			}

			dropIndex := outputRuleIndex(*captured, smtpDrop)
			bypassIndex := outputRuleIndex(*captured, tc.bypass)
			if dropIndex < 0 || bypassIndex < 0 {
				t.Fatalf("captured rule indexes: SMTP drop=%d family bypass=%d", dropIndex, bypassIndex)
			}
			if tc.bypassBefore && bypassIndex >= dropIndex {
				t.Fatalf("unmanaged-family bypass index %d must precede SMTP drop index %d", bypassIndex, dropIndex)
			}
			if !tc.bypassBefore && bypassIndex <= dropIndex {
				t.Fatalf("IPv4 bypass index %d must follow SMTP drop index %d", bypassIndex, dropIndex)
			}
		})
	}
}
