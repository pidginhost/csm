//go:build linux

package firewall

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
)

// Tests for Task 8: inverted-lookup helpers applied to connection meters.
//
// Compile-verified on macOS; full execution requires Linux with net_admin.
// Harness mirrors engine_dos_exempt_linux_test.go + port_flood_linux_test.go.

// findInvertedLookup returns the first *expr.Lookup with Invert==true found in
// exprs, or nil when none is present.
func findInvertedLookup(exprs []expr.Any) *expr.Lookup {
	for _, e := range exprs {
		if lk, ok := e.(*expr.Lookup); ok && lk.Invert {
			return lk
		}
	}
	return nil
}

// findLookupBySet returns the first *expr.Lookup (any Invert value) whose
// SetName matches name.
func findLookupBySet(exprs []expr.Any, name string) *expr.Lookup {
	for _, e := range exprs {
		if lk, ok := e.(*expr.Lookup); ok && lk.SetName == name {
			return lk
		}
	}
	return nil
}

// ---- helper tests for dosExemptV4Lookup / dosExemptV6Lookup ----------------

// TestDOSExemptV4LookupStructure verifies the helper returns the expected two
// expressions: a network-header Payload loading IPv4 saddr into reg, followed by
// an inverted Lookup into dos_exempt_nets.
func TestDOSExemptV4LookupStructure(t *testing.T) {
	set := &nftables.Set{Name: "dos_exempt_nets", ID: 7}
	e := &Engine{setDOSExempt: set}

	exprs := e.dosExemptV4Lookup(1)

	if len(exprs) != 2 {
		t.Fatalf("dosExemptV4Lookup len = %d, want 2", len(exprs))
	}
	p, ok := exprs[0].(*expr.Payload)
	if !ok {
		t.Fatal("exprs[0] must be *expr.Payload")
	}
	if p.Base != expr.PayloadBaseNetworkHeader {
		t.Errorf("Payload.Base = %v, want PayloadBaseNetworkHeader", p.Base)
	}
	if p.Offset != 12 || p.Len != 4 {
		t.Errorf("Payload offset/len = %d/%d, want 12/4 (IPv4 saddr)", p.Offset, p.Len)
	}
	if p.DestRegister != 1 {
		t.Errorf("Payload.DestRegister = %d, want 1", p.DestRegister)
	}
	lk, ok := exprs[1].(*expr.Lookup)
	if !ok {
		t.Fatal("exprs[1] must be *expr.Lookup")
	}
	if !lk.Invert {
		t.Error("Lookup.Invert must be true (skip rule for exempt sources)")
	}
	if lk.SetName != "dos_exempt_nets" || lk.SetID != 7 {
		t.Errorf("Lookup set = %s/%d, want dos_exempt_nets/7", lk.SetName, lk.SetID)
	}
	if lk.SourceRegister != 1 {
		t.Errorf("Lookup.SourceRegister = %d, want 1", lk.SourceRegister)
	}
}

// TestDOSExemptV6LookupStructure verifies the IPv6 analogue with offset 8,
// length 16, against dos_exempt_nets6.
func TestDOSExemptV6LookupStructure(t *testing.T) {
	set6 := &nftables.Set{Name: "dos_exempt_nets6", ID: 8}
	e := &Engine{setDOSExempt6: set6}

	exprs := e.dosExemptV6Lookup(1)

	if len(exprs) != 2 {
		t.Fatalf("dosExemptV6Lookup len = %d, want 2", len(exprs))
	}
	p, ok := exprs[0].(*expr.Payload)
	if !ok {
		t.Fatal("exprs[0] must be *expr.Payload")
	}
	if p.Base != expr.PayloadBaseNetworkHeader {
		t.Errorf("Payload.Base = %v, want PayloadBaseNetworkHeader", p.Base)
	}
	if p.Offset != 8 || p.Len != 16 {
		t.Errorf("Payload offset/len = %d/%d, want 8/16 (IPv6 saddr)", p.Offset, p.Len)
	}
	lk, ok := exprs[1].(*expr.Lookup)
	if !ok {
		t.Fatal("exprs[1] must be *expr.Lookup")
	}
	if !lk.Invert {
		t.Error("Lookup.Invert must be true")
	}
	if lk.SetName != "dos_exempt_nets6" || lk.SetID != 8 {
		t.Errorf("Lookup set = %s/%d, want dos_exempt_nets6/8", lk.SetName, lk.SetID)
	}
}

// ---- main assertion: conn meters carry the exempt lookup -------------------

// TestConnMetersCarryDOSExemptLookup verifies that when setDOSExempt is
// non-nil, both connMeterRuleExprs and connlimitRuleExprs begin with an
// inverted source-set lookup against dos_exempt_nets, so exempt sources (e.g.
// mail-provider CGNAT) are never metered.
//
// Precedence regression: the exempt lookup is prepended to the meter rule's
// own Exprs slice; it does NOT reorder chain rules. Blocked-IP and
// blocked-subnet drop rules are added earlier in createInputChain() (Rules 5-6)
// and will drop a blocked IP regardless of whether it is also in the exempt set.
// A packet from a blocked+exempt IP is dropped by the blocked_ips set-match
// rule before it ever reaches the connection meter rule.
func TestConnMetersCarryDOSExemptLookup(t *testing.T) {
	exemptSet := &nftables.Set{Name: "dos_exempt_nets", ID: 42}
	meterConn := &nftables.Set{Name: "meter_conn", ID: 1}
	meterConnlim := &nftables.Set{Name: "meter_connlimit", ID: 2}

	e := &Engine{
		cfg:          &FirewallConfig{ConnRateLimit: 50, ConnLimit: 10},
		setDOSExempt: exemptSet,
		meterConn:    meterConn,
		meterConnlim: meterConnlim,
	}

	// meter_conn
	connExprs := e.connMeterRuleExprs(50, 25)
	lk := findInvertedLookup(connExprs)
	if lk == nil {
		t.Fatal("meter_conn: no inverted Lookup found; expected dos_exempt_nets guard")
	}
	if lk.SetName != "dos_exempt_nets" || lk.SetID != 42 {
		t.Errorf("meter_conn: Lookup set = %s/%d, want dos_exempt_nets/42", lk.SetName, lk.SetID)
	}

	// meter_connlimit
	limExprs := e.connlimitRuleExprs(10)
	lk2 := findInvertedLookup(limExprs)
	if lk2 == nil {
		t.Fatal("meter_connlimit: no inverted Lookup found; expected dos_exempt_nets guard")
	}
	if lk2.SetName != "dos_exempt_nets" || lk2.SetID != 42 {
		t.Errorf("meter_connlimit: Lookup set = %s/%d, want dos_exempt_nets/42", lk2.SetName, lk2.SetID)
	}
}

// TestConnMeterNoExemptWhenSetNil verifies that no inverted Lookup is added to
// connMeterRuleExprs or connlimitRuleExprs when setDOSExempt is nil.
func TestConnMeterNoExemptWhenSetNil(t *testing.T) {
	meterConn := &nftables.Set{Name: "meter_conn", ID: 1}
	meterConnlim := &nftables.Set{Name: "meter_connlimit", ID: 2}

	e := &Engine{
		cfg: &FirewallConfig{ConnRateLimit: 50, ConnLimit: 10},
		// setDOSExempt intentionally nil
		meterConn:    meterConn,
		meterConnlim: meterConnlim,
	}

	connExprs := e.connMeterRuleExprs(50, 25)
	if lk := findInvertedLookup(connExprs); lk != nil {
		t.Errorf("meter_conn: unexpected inverted Lookup %s when setDOSExempt is nil", lk.SetName)
	}

	limExprs := e.connlimitRuleExprs(10)
	if lk := findInvertedLookup(limExprs); lk != nil {
		t.Errorf("meter_connlimit: unexpected inverted Lookup %s when setDOSExempt is nil", lk.SetName)
	}
}

// TestSYNMeterHasNoExemptLookup verifies that the SYN flood meter rule does
// NOT gain the dos_exempt_nets inverted lookup. The SYN meter already resets
// register 1 with protocol+flag checks before the source-IP load, so adding
// the lookup there would require a different register strategy. Task 8 leaves
// meter_syn unmodified.
func TestSYNMeterHasNoExemptLookup(t *testing.T) {
	exemptSet := &nftables.Set{Name: "dos_exempt_nets", ID: 42}
	meterSYN := &nftables.Set{Name: "meter_syn", ID: 3}

	e := &Engine{
		cfg:          &FirewallConfig{SYNFloodProtection: true},
		setDOSExempt: exemptSet,
		meterSYN:     meterSYN,
	}

	// synFloodRuleExprs is the extractor for the SYN meter rule; it must
	// return exactly the unchanged expressions (no inverted Lookup).
	exprs := e.synFloodRuleExprs()
	if lk := findInvertedLookup(exprs); lk != nil {
		t.Errorf("meter_syn: unexpected inverted Lookup %s; SYN meter must not carry exempt guard", lk.SetName)
	}
	if lk := findLookupBySet(exprs, "dos_exempt_nets"); lk != nil {
		t.Errorf("meter_syn: lookup into dos_exempt_nets found; SYN meter must remain unmodified")
	}
}

// TestUDPMeterHasNoExemptLookup verifies that the UDP flood meter rule does
// NOT gain the dos_exempt_nets inverted lookup. Task 8 leaves meter_udp unmodified.
func TestUDPMeterHasNoExemptLookup(t *testing.T) {
	exemptSet := &nftables.Set{Name: "dos_exempt_nets", ID: 42}
	meterUDP := &nftables.Set{Name: "meter_udp", ID: 4}

	e := &Engine{
		cfg:          &FirewallConfig{UDPFlood: true, UDPFloodRate: 100, UDPFloodBurst: 20},
		setDOSExempt: exemptSet,
		meterUDP:     meterUDP,
	}

	// udpFloodRuleExprs is the extractor for the UDP meter rule.
	exprs := e.udpFloodRuleExprs(100, 20)
	if lk := findInvertedLookup(exprs); lk != nil {
		t.Errorf("meter_udp: unexpected inverted Lookup %s; UDP meter must not carry exempt guard", lk.SetName)
	}
	if lk := findLookupBySet(exprs, "dos_exempt_nets"); lk != nil {
		t.Errorf("meter_udp: lookup into dos_exempt_nets found; UDP meter must remain unmodified")
	}
}

// ---- lookup position and register-reuse correctness -----------------------

// TestConnMeterExemptLookupPrecedesCtExprs verifies the expression order of
// connMeterRuleExprs: the NFPROTO==IPV4 guard pair first, then the exempt
// Payload+Lookup, then the Ct state check. The exempt lookup short-circuits the
// rule for exempt sources before conntrack is evaluated; the guard ensures the
// exempt lookup's IPv4 saddr load only runs on IPv4 packets. Each following expr
// reloads register 1 independently, so the register reuse is safe.
func TestConnMeterExemptLookupPrecedesCtExprs(t *testing.T) {
	exemptSet := &nftables.Set{Name: "dos_exempt_nets", ID: 42}
	meterConn := &nftables.Set{Name: "meter_conn", ID: 1}

	e := &Engine{
		cfg:          &FirewallConfig{ConnRateLimit: 50},
		setDOSExempt: exemptSet,
		meterConn:    meterConn,
	}

	exprs := e.connMeterRuleExprs(50, 25)

	assertIPv4NFProtoGuardPrefix(t, exprs)

	// exprs[2] must be the exempt Payload (saddr into reg 1)
	p, ok := exprs[2].(*expr.Payload)
	if !ok {
		t.Fatalf("exprs[2] = %T, want *expr.Payload (exempt saddr load)", exprs[2])
	}
	if p.Base != expr.PayloadBaseNetworkHeader || p.Offset != 12 || p.Len != 4 {
		t.Errorf("exprs[2] Payload base/offset/len = %v/%d/%d, want NetworkHeader/12/4",
			p.Base, p.Offset, p.Len)
	}

	// exprs[3] must be the inverted Lookup
	lk, ok := exprs[3].(*expr.Lookup)
	if !ok || !lk.Invert {
		t.Fatalf("exprs[3] = %T Invert=%v, want inverted *expr.Lookup", exprs[3], ok)
	}

	// exprs[4] must be Ct (the ct state check, after guard + exempt pair)
	if _, ok := exprs[4].(*expr.Ct); !ok {
		t.Errorf("exprs[4] = %T, want *expr.Ct (ct state check)", exprs[4])
	}

	// The rule must still end with VerdictDrop
	if !endsWithDrop(exprs) {
		t.Error("connMeterRuleExprs must end with VerdictDrop")
	}
}

// TestConnlimitExemptLookupPrecedesCtExprs mirrors the above for connlimitRuleExprs.
func TestConnlimitExemptLookupPrecedesCtExprs(t *testing.T) {
	exemptSet := &nftables.Set{Name: "dos_exempt_nets", ID: 42}
	meterConnlim := &nftables.Set{Name: "meter_connlimit", ID: 2}

	e := &Engine{
		cfg:          &FirewallConfig{ConnLimit: 10},
		setDOSExempt: exemptSet,
		meterConnlim: meterConnlim,
	}

	exprs := e.connlimitRuleExprs(10)

	assertIPv4NFProtoGuardPrefix(t, exprs)

	if _, ok := exprs[2].(*expr.Payload); !ok {
		t.Fatalf("exprs[2] = %T, want *expr.Payload (exempt saddr load)", exprs[2])
	}
	lk, ok := exprs[3].(*expr.Lookup)
	if !ok || !lk.Invert {
		t.Fatalf("exprs[3] = %T Invert=%v, want inverted *expr.Lookup", exprs[3], ok)
	}
	if _, ok := exprs[4].(*expr.Ct); !ok {
		t.Errorf("exprs[4] = %T, want *expr.Ct", exprs[4])
	}
	if !endsWithDrop(exprs) {
		t.Error("connlimitRuleExprs must end with VerdictDrop")
	}
}

// ---- precedence regression: blocked drops run before the exempt meters -----

// nftConnCapturingRules returns a test nftables.Conn whose dial records, in
// order, every netlink message sent on Flush into *captured, and ACKs the batch
// so Flush succeeds. The ACK construction mirrors the success branch of
// nftConnReturningErrsThenOK. *captured holds the full flushed batch; rule
// messages carry their referenced set names as null-terminated strings, which is
// what the precedence test searches for.
func nftConnCapturingRules(t *testing.T) (*nftables.Conn, *[]netlink.Message) {
	t.Helper()
	captured := &[]netlink.Message{}
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, io.EOF
		}
		*captured = append(*captured, req...)
		acks := make([]netlink.Message, 0, len(req))
		for _, msg := range req {
			if msg.Header.Flags&netlink.Acknowledge == 0 {
				continue
			}
			acks = append(acks, netlink.Message{
				Header: netlink.Header{
					Length:   4,
					Type:     netlink.Error,
					Sequence: msg.Header.Sequence,
					PID:      msg.Header.PID,
				},
				Data: []byte{0, 0, 0, 0},
			})
		}
		return acks, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return conn, captured
}

// ruleMsgIndexForSet returns the index of the first captured message whose
// marshaled body references the named nftables set (set names are encoded as
// null-terminated strings in NFTA_LOOKUP_SET / NFTA_DYNSET_SET_NAME). The "\x00"
// terminator prevents prefix collisions (e.g. "meter_conn" vs "meter_connlimit",
// "dos_exempt_nets" vs "dos_exempt_nets6").
func ruleMsgIndexForSet(msgs []netlink.Message, setName string) int {
	needle := []byte(setName + "\x00")
	for i, m := range msgs {
		if bytes.Contains(m.Data, needle) {
			return i
		}
	}
	return -1
}

// ruleMsgReferencesSet reports whether a single captured message references the
// named set.
func ruleMsgReferencesSet(m netlink.Message, setName string) bool {
	return bytes.Contains(m.Data, []byte(setName+"\x00"))
}

// TestBlockedDropsPrecedeConnMeters is the precedence regression guard for the
// DoS-exempt feature's security acceptance criterion: a manually blocked IP or
// subnet that also falls inside a dos_exempt range must STILL be dropped.
//
// The blocked_ips and blocked_nets drop rules are added to the input chain
// BEFORE the connection-meter rules, so the unconditional drop is evaluated
// first; the inverted dos_exempt lookup only short-circuits the later meters.
// This builds the real input chain through the mock-conn harness, captures the
// ordered rule messages, and locks both the source ordering and the fact that
// the drop rules carry no exempt lookup (so an exempt-range membership can never
// rescue a blocked source).
func TestBlockedDropsPrecedeConnMeters(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := &Engine{
		cfg:       &FirewallConfig{ConnRateLimit: 50, ConnLimit: 10},
		conn:      conn,
		statePath: t.TempDir(),
	}
	e.table = conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})
	e.setBlocked = &nftables.Set{Table: e.table, Name: "blocked_ips", KeyType: nftables.TypeIPAddr}
	e.setBlockedNet = &nftables.Set{Table: e.table, Name: "blocked_nets", KeyType: nftables.TypeIPAddr, Interval: true}
	e.meterConn = &nftables.Set{Table: e.table, Name: "meter_conn", KeyType: nftables.TypeIPAddr, Dynamic: true}
	e.meterConnlim = &nftables.Set{Table: e.table, Name: "meter_connlimit", KeyType: nftables.TypeIPAddr, Dynamic: true}
	e.setDOSExempt = &nftables.Set{Table: e.table, Name: "dos_exempt_nets", KeyType: nftables.TypeIPAddr, Interval: true}

	if err := e.createInputChain(); err != nil {
		t.Fatalf("createInputChain: %v", err)
	}
	if err := e.conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	msgs := *captured
	idxBlockedIPs := ruleMsgIndexForSet(msgs, "blocked_ips")
	idxBlockedNets := ruleMsgIndexForSet(msgs, "blocked_nets")
	idxMeterConn := ruleMsgIndexForSet(msgs, "meter_conn")
	idxMeterConnlim := ruleMsgIndexForSet(msgs, "meter_connlimit")

	if idxBlockedIPs < 0 {
		t.Fatal("no blocked_ips drop rule captured")
	}
	if idxBlockedNets < 0 {
		t.Fatal("no blocked_nets drop rule captured")
	}
	if idxMeterConn < 0 {
		t.Fatal("no meter_conn rule captured")
	}
	if idxMeterConnlim < 0 {
		t.Fatal("no meter_connlimit rule captured")
	}

	// Drops must be evaluated before the metering rules.
	if idxBlockedIPs >= idxMeterConn {
		t.Errorf("blocked_ips drop (idx %d) must precede meter_conn (idx %d)", idxBlockedIPs, idxMeterConn)
	}
	if idxBlockedNets >= idxMeterConn {
		t.Errorf("blocked_nets drop (idx %d) must precede meter_conn (idx %d)", idxBlockedNets, idxMeterConn)
	}
	if idxBlockedIPs >= idxMeterConnlim {
		t.Errorf("blocked_ips drop (idx %d) must precede meter_connlimit (idx %d)", idxBlockedIPs, idxMeterConnlim)
	}
	if idxBlockedNets >= idxMeterConnlim {
		t.Errorf("blocked_nets drop (idx %d) must precede meter_connlimit (idx %d)", idxBlockedNets, idxMeterConnlim)
	}

	// The drops are unconditional: they must NOT reference dos_exempt_nets,
	// otherwise a blocked IP/subnet inside an exempt range would slip through.
	if ruleMsgReferencesSet(msgs[idxBlockedIPs], "dos_exempt_nets") {
		t.Error("blocked_ips drop rule must not reference dos_exempt_nets (drop must be unconditional)")
	}
	if ruleMsgReferencesSet(msgs[idxBlockedNets], "dos_exempt_nets") {
		t.Error("blocked_nets drop rule must not reference dos_exempt_nets (drop must be unconditional)")
	}

	// Positive control: the meters DO carry the exempt guard, confirming the
	// capture distinguishes exempt-bearing rules from the bare drops.
	if !ruleMsgReferencesSet(msgs[idxMeterConn], "dos_exempt_nets") {
		t.Error("meter_conn rule must reference dos_exempt_nets (exempt guard)")
	}
	if !ruleMsgReferencesSet(msgs[idxMeterConnlim], "dos_exempt_nets") {
		t.Error("meter_connlimit rule must reference dos_exempt_nets (exempt guard)")
	}
}
