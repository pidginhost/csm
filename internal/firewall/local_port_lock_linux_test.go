//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
)

func lockMatchForTest(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("lo\x00")},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		// A connection-opening segment: SYN set, ACK clear. Matching the TCP
		// flags rather than conntrack keeps the lock working where loopback
		// traffic is not tracked.
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x12}, Xor: []byte{0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}},
	}
}

func lockAcceptForTest(port uint16, uid uint32) []expr.Any {
	return append(lockMatchForTest(port),
		&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uid)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
}

func lockRejectForTest(port uint16) []expr.Any {
	return append(lockMatchForTest(port), &expr.Reject{Type: 1})
}

func loopbackAcceptForTest() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("lo\x00")},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// captureLockRuleData renders one output rule and returns its netlink
// message. Unlike captureOutputRuleData it also finds a rule with no verdict
// (the reject).
func captureLockRuleData(t *testing.T, exprs []expr.Any) []byte {
	t.Helper()
	conn, captured := nftConnCapturingRules(t)
	table := conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})
	chain := conn.AddChain(&nftables.Chain{Name: "output", Table: table})
	conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	for _, msg := range *captured {
		if bytes.Contains(msg.Data, []byte("meta\x00")) {
			return append([]byte(nil), msg.Data...)
		}
	}
	t.Fatal("captured batch has no rule message")
	return nil
}

func buildOutputChainForTest(t *testing.T, cfg *FirewallConfig) []netlink.Message {
	t.Helper()
	conn, captured := nftConnCapturingRules(t)
	e := &Engine{cfg: cfg, conn: conn}
	e.table = conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})
	if err := e.createOutputChain(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	return *captured
}

func withLockUsers(t *testing.T, table map[string]string) {
	t.Helper()
	prev := localPortLockLookupUser
	localPortLockLookupUser = fixtureLookupUser(t, table)
	t.Cleanup(func() { localPortLockLookupUser = prev })
}

func TestLocalPortLockMatchesOnlyNewLoopbackConnections(t *testing.T) {
	withLockUsers(t, map[string]string{"www-data": "33"})
	rootAccept := captureLockRuleData(t, lockAcceptForTest(8080, 0))
	userAccept := captureLockRuleData(t, lockAcceptForTest(8080, 33))
	reject := captureLockRuleData(t, lockRejectForTest(8080))
	loopback := captureLockRuleData(t, loopbackAcceptForTest())

	for _, tc := range []struct {
		name string
		cfg  *FirewallConfig
	}{
		{"restricted output", &FirewallConfig{TCPOut: []int{443}, LocalPortLocks: []string{"8080:www-data"}}},
		{"open output", &FirewallConfig{LocalPortLocks: []string{"8080:www-data"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msgs := buildOutputChainForTest(t, tc.cfg)
			ri, ui, xi := outputRuleIndex(msgs, rootAccept), outputRuleIndex(msgs, userAccept), outputRuleIndex(msgs, reject)
			if ri < 0 || ui < 0 || xi < 0 {
				t.Fatalf("lock rules missing: root=%d user=%d reject=%d", ri, ui, xi)
			}
			if xi < ri || xi < ui {
				t.Fatalf("reject at %d precedes an allowed user (root %d, www-data %d)", xi, ri, ui)
			}
			if li := outputRuleIndex(msgs, loopback); li >= 0 && li < xi {
				t.Fatalf("loopback accept at %d precedes the lock reject at %d", li, xi)
			}
		})
	}
}

func TestLocalPortLockAbsentRendersNothing(t *testing.T) {
	reject := captureLockRuleData(t, lockRejectForTest(8080))
	for _, cfg := range []*FirewallConfig{{TCPOut: []int{443}}, {}} {
		if outputRuleIndex(buildOutputChainForTest(t, cfg), reject) >= 0 {
			t.Fatal("a lock rule was rendered without local_port_locks")
		}
	}
}

func TestLocalPortLockUnknownUserFailsClosed(t *testing.T) {
	withLockUsers(t, map[string]string{})
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prevStderr := os.Stderr
	os.Stderr = w
	msgs := buildOutputChainForTest(t, &FirewallConfig{LocalPortLocks: []string{"8080:ghost"}})
	os.Stderr = prevStderr
	_ = w.Close()
	stderr, _ := io.ReadAll(r)

	if outputRuleIndex(msgs, captureLockRuleData(t, lockRejectForTest(8080))) < 0 {
		t.Fatal("the reject was not installed when a user is unknown")
	}
	if outputRuleIndex(msgs, captureLockRuleData(t, lockAcceptForTest(8080, 0))) < 0 {
		t.Fatal("root lost access when a user is unknown")
	}
	if !strings.Contains(string(stderr), `unknown user "ghost"`) {
		t.Fatalf("stderr = %q, want an unknown user warning", stderr)
	}
}

// Only an acknowledged kernel transaction establishes a port lock.
func TestLockedLocalPortsReportsAppliedRules(t *testing.T) {
	withLockUsers(t, map[string]string{"web": "33"})
	conn, _ := nftConnCapturingRules(t)
	e := &Engine{conn: conn, cfg: &FirewallConfig{LocalPortLocks: []string{"8080:web"}}, statePath: t.TempDir(),
		listTables:  func() ([]*nftables.Table, error) { return nil, nil },
		readRuleset: func() (string, error) { return "rules", nil },
	}
	if got := e.LockedLocalPorts(); len(got) != 0 {
		t.Fatal("unapplied lock reported active")
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if got := e.LockedLocalPorts(); !reflect.DeepEqual(got, []int{8080}) {
		t.Fatalf("applied locks = %v", got)
	}
	e.SetConfig(&FirewallConfig{LocalPortLocks: []string{"9000:web"}})
	e.listTables = func() ([]*nftables.Table, error) { return nil, errors.New("unavailable") }
	if err := e.Apply(); err == nil {
		t.Fatal("expected failed apply")
	}
	if got := e.LockedLocalPorts(); !reflect.DeepEqual(got, []int{8080}) {
		t.Fatalf("failed apply changed reported locks: %v", got)
	}
	e.listTables = func() ([]*nftables.Table, error) { return nil, nil }
	e.conn = nftConnReturningErr(t, syscall.EPERM)
	if err := e.Apply(); err == nil {
		t.Fatal("expected rejected kernel transaction")
	}
	if got := e.LockedLocalPorts(); !reflect.DeepEqual(got, []int{8080}) {
		t.Fatalf("rejected transaction changed locks: %v", got)
	}
	e.conn = conn
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if got := e.LockedLocalPorts(); !reflect.DeepEqual(got, []int{9000}) {
		t.Fatalf("replacement locks = %v", got)
	}
	e.SetConfig(&FirewallConfig{})
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if got := e.LockedLocalPorts(); len(got) != 0 {
		t.Fatal("removed lock reported active")
	}
}

func TestLockedLocalPortsRejectsUnprovenLiveRules(t *testing.T) {
	withLockUsers(t, map[string]string{"web": "33"})
	conn, _ := nftConnCapturingRules(t)
	live := "protected rules"
	var readErr error
	e := &Engine{conn: conn, cfg: &FirewallConfig{LocalPortLocks: []string{"8080:web"}}, statePath: t.TempDir(),
		listTables:  func() ([]*nftables.Table, error) { return nil, nil },
		readRuleset: func() (string, error) { return live, readErr },
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if got := e.LockedLocalPorts(); !reflect.DeepEqual(got, []int{8080}) {
		t.Fatal("installed lock not reported")
	}
	live = "previous rules without locks"
	e.SetConfig(&FirewallConfig{})
	if got := e.LockedLocalPorts(); len(got) != 0 {
		t.Fatal("rollback left stale lock protection")
	}
	live = "protected rules"
	readErr = errors.New("cannot inspect rules")
	if got := e.LockedLocalPorts(); len(got) != 0 {
		t.Fatal("unreadable live rules reported protected")
	}
	e.SetConfig(&FirewallConfig{LocalPortLocks: []string{"8080:web"}})
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	readErr = nil
	if got := e.LockedLocalPorts(); len(got) != 0 {
		t.Fatal("missing installation baseline reported protected")
	}
}
