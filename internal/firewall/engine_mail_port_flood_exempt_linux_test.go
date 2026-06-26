//go:build linux

package firewall

// Tests for Task 9: inverted-lookup helpers applied to mail port-flood meters.
//
// Compile-verified on macOS; full execution requires Linux with net_admin.
// Harness mirrors engine_conn_meter_exempt_linux_test.go.
//
// Family report: the port-flood loop in engine.go always emits an IPv4 rule per
// PortFloodRule entry and, when cfg.IPv6==true, also an IPv6 rule. Both families
// must carry the family-appropriate exempt lookup for mail TCP ports.

import (
	"testing"

	"github.com/google/nftables"
)

// TestIsMailTCP verifies the isMailTCP classifier for port_flood rules.
func TestIsMailTCP(t *testing.T) {
	cases := []struct {
		pf   PortFloodRule
		want bool
		desc string
	}{
		{PortFloodRule{Port: 25, Proto: "tcp"}, true, "SMTP"},
		{PortFloodRule{Port: 465, Proto: "tcp"}, true, "SMTPS"},
		{PortFloodRule{Port: 587, Proto: "tcp"}, true, "submission"},
		{PortFloodRule{Port: 25, Proto: "TCP"}, true, "SMTP uppercase"},
		{PortFloodRule{Port: 25, Proto: "Tcp"}, true, "SMTP mixed case"},
		{PortFloodRule{Port: 443, Proto: "tcp"}, false, "HTTPS (non-mail)"},
		{PortFloodRule{Port: 80, Proto: "tcp"}, false, "HTTP (non-mail)"},
		{PortFloodRule{Port: 25, Proto: "udp"}, false, "UDP port 25"},
		{PortFloodRule{Port: 465, Proto: "udp"}, false, "UDP port 465"},
		{PortFloodRule{Port: 587, Proto: "udp"}, false, "UDP port 587"},
		{PortFloodRule{Port: 0, Proto: "tcp"}, false, "zero port"},
	}
	for _, tc := range cases {
		got := isMailTCP(tc.pf)
		if got != tc.want {
			t.Errorf("isMailTCP(%+v) [%s] = %v, want %v", tc.pf, tc.desc, got, tc.want)
		}
	}
}

// TestMailPortFloodMetersCarryDOSExemptLookup verifies that when setDOSExempt
// and setDOSExempt6 are non-nil, the port_flood rules for TCP 25/465/587 carry
// the inverted dos_exempt_nets (v4) and dos_exempt_nets6 (v6) lookups. A non-mail
// TCP port (443) and a UDP mail port (25) must not carry the exempt lookup.
//
// Captured rule messages from createInputChain each encode all expression set
// references as null-terminated strings, so a message for a mail meter rule with
// the exempt guard prepended will contain BOTH the meter name and the exempt set
// name. A rule without the guard contains only the meter name.
func TestMailPortFloodMetersCarryDOSExemptLookup(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)

	pfs := []PortFloodRule{
		{Port: 25, Proto: "tcp", Hits: 600, Seconds: 300},
		{Port: 465, Proto: "tcp", Hits: 600, Seconds: 300},
		{Port: 587, Proto: "tcp", Hits: 600, Seconds: 300},
		{Port: 443, Proto: "tcp", Hits: 600, Seconds: 300}, // non-mail TCP
		{Port: 25, Proto: "udp", Hits: 600, Seconds: 300},  // UDP -- must not carry exempt
	}

	meterPortFlood4 := make(map[string]*nftables.Set)
	meterPortFlood6 := make(map[string]*nftables.Set)
	for i, pf := range pfs {
		n4 := portFloodMeterName(pf, portFloodIPv4)
		meterPortFlood4[n4] = &nftables.Set{Name: n4, ID: uint32(10 + i*2)}
		n6 := portFloodMeterName(pf, portFloodIPv6)
		meterPortFlood6[n6] = &nftables.Set{Name: n6, ID: uint32(11 + i*2)}
	}

	exemptV4 := &nftables.Set{Name: "dos_exempt_nets", ID: 100}
	exemptV6 := &nftables.Set{Name: "dos_exempt_nets6", ID: 101}

	e := &Engine{
		cfg: &FirewallConfig{
			IPv6:      true,
			PortFlood: pfs,
		},
		conn:            conn,
		statePath:       t.TempDir(),
		meterPortFlood4: meterPortFlood4,
		meterPortFlood6: meterPortFlood6,
		setDOSExempt:    exemptV4,
		setDOSExempt6:   exemptV6,
	}
	e.table = conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})

	if err := e.createInputChain(); err != nil {
		t.Fatalf("createInputChain: %v", err)
	}
	if err := e.conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	msgs := *captured

	// Mail TCP ports: each v4 and v6 meter rule must carry the family-appropriate
	// exempt set reference in the same rule message as the meter dynset.
	for _, port := range []int{25, 465, 587} {
		pf := PortFloodRule{Port: port, Proto: "tcp"}

		// IPv4 meter rule
		n4 := portFloodMeterName(pf, portFloodIPv4)
		foundV4 := false
		for _, msg := range msgs {
			if !ruleMsgReferencesSet(msg, n4) {
				continue
			}
			foundV4 = true
			if !ruleMsgReferencesSet(msg, "dos_exempt_nets") {
				t.Errorf("mail port %d TCP v4: rule with %s does not carry dos_exempt_nets guard", port, n4)
			}
		}
		if !foundV4 {
			t.Errorf("mail port %d TCP v4: no captured rule references %s", port, n4)
		}

		// IPv6 meter rule
		n6 := portFloodMeterName(pf, portFloodIPv6)
		foundV6 := false
		for _, msg := range msgs {
			if !ruleMsgReferencesSet(msg, n6) {
				continue
			}
			foundV6 = true
			if !ruleMsgReferencesSet(msg, "dos_exempt_nets6") {
				t.Errorf("mail port %d TCP v6: rule with %s does not carry dos_exempt_nets6 guard", port, n6)
			}
		}
		if !foundV6 {
			t.Errorf("mail port %d TCP v6: no captured rule references %s", port, n6)
		}
	}

	// Non-mail TCP 443: must NOT carry the exempt lookup.
	pf443 := PortFloodRule{Port: 443, Proto: "tcp"}
	for _, msg := range msgs {
		if ruleMsgReferencesSet(msg, portFloodMeterName(pf443, portFloodIPv4)) {
			if ruleMsgReferencesSet(msg, "dos_exempt_nets") {
				t.Error("non-mail TCP 443 v4: rule must not carry dos_exempt_nets guard")
			}
		}
		if ruleMsgReferencesSet(msg, portFloodMeterName(pf443, portFloodIPv6)) {
			if ruleMsgReferencesSet(msg, "dos_exempt_nets6") {
				t.Error("non-mail TCP 443 v6: rule must not carry dos_exempt_nets6 guard")
			}
		}
	}

	// UDP port 25: must NOT carry the exempt lookup regardless of port number.
	pfUDP := PortFloodRule{Port: 25, Proto: "udp"}
	for _, msg := range msgs {
		if ruleMsgReferencesSet(msg, portFloodMeterName(pfUDP, portFloodIPv4)) {
			if ruleMsgReferencesSet(msg, "dos_exempt_nets") {
				t.Error("UDP port 25 v4: rule must not carry dos_exempt_nets guard")
			}
		}
		if ruleMsgReferencesSet(msg, portFloodMeterName(pfUDP, portFloodIPv6)) {
			if ruleMsgReferencesSet(msg, "dos_exempt_nets6") {
				t.Error("UDP port 25 v6: rule must not carry dos_exempt_nets6 guard")
			}
		}
	}
}

// TestMailPortFloodMetersNoExemptWhenSetNil verifies that no exempt lookup is
// added to mail TCP port rules when setDOSExempt (v4) or setDOSExempt6 (v6) is nil.
func TestMailPortFloodMetersNoExemptWhenSetNil(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)

	pf := PortFloodRule{Port: 25, Proto: "tcp", Hits: 600, Seconds: 300}
	n4 := portFloodMeterName(pf, portFloodIPv4)
	n6 := portFloodMeterName(pf, portFloodIPv6)

	meterPortFlood4 := map[string]*nftables.Set{n4: {Name: n4, ID: 10}}
	meterPortFlood6 := map[string]*nftables.Set{n6: {Name: n6, ID: 11}}

	e := &Engine{
		cfg: &FirewallConfig{
			IPv6:      true,
			PortFlood: []PortFloodRule{pf},
		},
		conn:            conn,
		statePath:       t.TempDir(),
		meterPortFlood4: meterPortFlood4,
		meterPortFlood6: meterPortFlood6,
		// setDOSExempt and setDOSExempt6 intentionally nil
	}
	e.table = conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})

	if err := e.createInputChain(); err != nil {
		t.Fatalf("createInputChain: %v", err)
	}
	if err := e.conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	for _, msg := range *captured {
		if ruleMsgReferencesSet(msg, n4) && ruleMsgReferencesSet(msg, "dos_exempt_nets") {
			t.Error("TCP 25 v4: exempt guard must not appear when setDOSExempt is nil")
		}
		if ruleMsgReferencesSet(msg, n6) && ruleMsgReferencesSet(msg, "dos_exempt_nets6") {
			t.Error("TCP 25 v6: exempt guard must not appear when setDOSExempt6 is nil")
		}
	}
}
