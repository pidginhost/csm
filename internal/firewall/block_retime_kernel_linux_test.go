//go:build linux && nftkernel

package firewall

import (
	"testing"
	"time"

	"github.com/google/nftables"
)

// kernelStaleTimer gives the element of ip the timeout a restored dump
// would: the time it had left when the dump was taken, more than its row
// has left now.
func kernelStaleTimer(t *testing.T, e *Engine, ip string, timeout time.Duration) {
	t.Helper()
	set, key, err := e.resolveIPSet(ip, e.setBlocked, e.setBlocked6)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.conn.SetDeleteElements(set, []nftables.SetElement{{Key: key}}); err != nil {
		t.Fatal(err)
	}
	if err = e.conn.SetAddElements(set, []nftables.SetElement{{Key: key, Timeout: timeout}}); err != nil {
		t.Fatal(err)
	}
	if err = e.conn.Flush(); err != nil {
		t.Fatal(err)
	}
}

func kernelRowProvesElement(t *testing.T, e *Engine, ip string) bool {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	snap, err := e.blockSnapshotLocked()
	if err != nil {
		t.Fatal(err)
	}
	observed, live := snap.live[ip]
	return snap.proves(snap.blocked[stateIPKey(ip)], observed, live)
}

// A ruleset restored from a dump gives each timed block the time it had
// left when the dump was taken, so no row proves its element any more.
// Retiming puts every element back on its row's time in each family,
// keeps a permanent block permanent, and drops an element no row names.
func TestKernelRetimeBlocksRestoresRowLifetimes(t *testing.T) {
	e := newKernelBatchEngine(t)
	v4, v6 := kernelBlockMember("act_retime4", "203.0.113.70", time.Hour), kernelBlockMember("act_retime6", "2001:db8::70", time.Hour)
	if results, err := e.ApplyBlockBatch([]BlockMember{v4, v6}); err != nil || effects(results) != "applied/ applied/" {
		t.Fatalf("batch = %+v, %v", results, err)
	}
	if err := e.BlockIPForce("203.0.113.71", "operator", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := e.BlockIPForce("203.0.113.72", "operator", 0); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{v4.IP, v6.IP, "203.0.113.71"} {
		kernelStaleTimer(t, e, ip, 2*time.Hour)
	}
	if err := e.conn.SetAddElements(e.setBlocked, []nftables.SetElement{{Key: []byte{203, 0, 113, 79}, Timeout: time.Hour}}); err != nil {
		t.Fatal(err)
	}
	if err := e.conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if kernelRowProvesElement(t, e, v4.IP) || kernelRowProvesElement(t, e, v6.IP) {
		t.Fatal("a row proved an element with a stale timer")
	}

	if err := e.RetimeBlocks(); err != nil {
		t.Fatal(err)
	}
	if !kernelRowProvesElement(t, e, v4.IP) || !kernelRowProvesElement(t, e, v6.IP) {
		t.Fatal("a retimed element does not prove its row")
	}
	elements := kernelBlockElements(t, e, e.setBlocked)
	if left := elements["203.0.113.71"].Expires; left <= 29*time.Minute || left > 30*time.Minute {
		t.Fatalf("the operator's temporary block has %v left, want its row's 30 minutes", left)
	}
	if el, held := elements["203.0.113.72"]; !held || el.Timeout != 0 || el.Expires != 0 {
		t.Fatalf("the permanent block = %+v, held %v; want it without a timeout", el, held)
	}
	if _, held := elements["203.0.113.79"]; held {
		t.Fatal("an element no row names survived the retiming")
	}
}
