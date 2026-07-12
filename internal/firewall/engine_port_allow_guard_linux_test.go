//go:build linux

package firewall

import (
	"testing"

	"github.com/google/nftables"
)

func TestPortAllowIPv4GuardPrecedesSourceLoad(t *testing.T) {
	exprs := buildPortAllowExprs(PortAllowEntry{
		IP:    "198.51.100.24",
		Port:  3306,
		Proto: "tcp",
	}, true)

	assertIPv4NFProtoGuardPrefix(t, exprs)
}

func TestPortFloodIPv4ExemptionFollowsFamilyGuard(t *testing.T) {
	e := &Engine{
		setDOSExempt: &nftables.Set{Name: "dos_exempt_nets", ID: 42},
	}
	pf := PortFloodRule{Port: 25, Proto: "tcp", Hits: 600, Seconds: 300}
	meter := &nftables.Set{Name: "meter_pf_tcp_25_v4", ID: 7}

	exprs := e.portFloodRuleExprs(pf, meter, portFloodIPv4)

	assertIPv4NFProtoGuardPrefix(t, exprs)
}

func TestPortAllowIPv6GuardPrecedesSourceLoad(t *testing.T) {
	exprs := buildPortAllowExprs(PortAllowEntry{
		IP:    "2001:db8::24",
		Port:  3306,
		Proto: "tcp",
	}, true)

	assertIPv6NFProtoGuardPrefix(t, exprs)
}

func TestPortFloodIPv6ExemptionFollowsFamilyGuard(t *testing.T) {
	e := &Engine{
		setDOSExempt6: &nftables.Set{Name: "dos_exempt_nets6", ID: 43},
	}
	pf := PortFloodRule{Port: 25, Proto: "tcp", Hits: 600, Seconds: 300}
	meter := &nftables.Set{Name: "meter_pf_tcp_25_v6", ID: 8}

	exprs := e.portFloodRuleExprs(pf, meter, portFloodIPv6)

	assertIPv6NFProtoGuardPrefix(t, exprs)
}
