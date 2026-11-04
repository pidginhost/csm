//go:build linux && nftkernel

package firewall

import (
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Record Route (type 7, length 7, pointer 4) with one empty slot, padded to
// a 4-byte boundary with End of Options.
var recordRouteOption = []byte{7, 7, 4, 0, 0, 0, 0, 0}

func dialLoopback(addr string, options []byte) error {
	d := net.Dialer{Timeout: 750 * time.Millisecond}
	if options != nil {
		d.Control = func(_, _ string, raw syscall.RawConn) error {
			var setErr error
			if err := raw.Control(func(fd uintptr) {
				setErr = unix.SetsockoptString(int(fd), unix.IPPROTO_IP, unix.IP_OPTIONS, string(options))
			}); err != nil {
				return err
			}
			return setErr
		}
	}
	conn, err := d.Dial("tcp4", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// ipv4OptionsDrops returns the drop counter of the csm prerouting chain and
// whether the chain is installed.
func ipv4OptionsDrops(t *testing.T, e *Engine) (uint64, bool) {
	t.Helper()
	chains, err := e.conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range chains {
		if chain.Table.Name != "csm" || chain.Name != "prerouting" {
			continue
		}
		if chain.Hooknum == nil || *chain.Hooknum != *nftables.ChainHookPrerouting || chain.Priority == nil || *chain.Priority != -310 {
			t.Fatalf("prerouting chain hook=%v priority=%v, want prerouting at -310", chain.Hooknum, chain.Priority)
		}
		rules, err := e.conn.GetRules(e.table, chain)
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range rules {
			for _, ex := range rule.Exprs {
				if counter, ok := ex.(*expr.Counter); ok {
					return counter.Packets, true
				}
			}
		}
		t.Fatal("prerouting chain has no drop counter")
	}
	return 0, false
}

// Real loopback handshakes: a SYN carrying IP options never reaches the
// listener while the drop is on, a plain SYN always does, and switching the
// drop off and back on takes effect on the next apply.
func TestKernelDropsIPv4TCPWithOptions(t *testing.T) {
	isolatedFirewallNamespace(t)
	kernelLoopbackUp(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	addr := ln.Addr().String()

	cfg := &FirewallConfig{Enabled: true, DropIPv4Options: true}
	e, err := NewEngine(cfg, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, on := range []bool{true, false, true} {
		next := *cfg
		next.DropIPv4Options = on
		e.SetConfig(&next)
		if err = e.Apply(); err != nil {
			t.Fatal(err)
		}
		if err = dialLoopback(addr, nil); err != nil {
			t.Fatalf("drop_ipv4_options=%t: plain handshake failed: %v", on, err)
		}
		err = dialLoopback(addr, recordRouteOption)
		if on && err == nil {
			t.Fatal("handshake with IP options completed while the drop is on")
		}
		if !on && err != nil {
			t.Fatalf("handshake with IP options failed while the drop is off: %v", err)
		}
		drops, installed := ipv4OptionsDrops(t, e)
		if installed != on || (on && drops == 0) {
			t.Fatalf("drop_ipv4_options=%t: chain installed=%t drops=%d", on, installed, drops)
		}
		// Integrity monitoring compares structure; counted drops are traffic.
		current, applied, snapErr := e.RulesetSnapshot()
		if snapErr != nil || applied == "" || current != applied {
			t.Fatalf("drop_ipv4_options=%t: drops changed the ruleset snapshot: err=%v", on, snapErr)
		}
	}
}
