//go:build linux

package firewall

import (
	"net"
	"syscall"
	"testing"

	"github.com/google/nftables"
)

// Tests for dos_exempt_nets interval sets (Task 7).
//
// Harness: mirrors engine_methods_linux_test.go.
// createSets() queues messages into an nftables.Conn without calling Flush,
// so the test dialer is never invoked during set creation; AddSet succeeds
// purely in user space. RefreshDOSExemptSets calls Flush, so its error path
// uses nftConnReturningErr to simulate a kernel rejection.
//
// These tests are compile-verified on macOS and execute on Linux CI with root.

// dosExemptTestTable returns a bare table struct to attach to manually-built sets.
func dosExemptTestTable() *nftables.Table {
	return &nftables.Table{Name: "csm", Family: nftables.TableFamilyINet}
}

// TestDOSExemptSetsCreatedAsInterval verifies that createSets() assigns
// setDOSExempt and setDOSExempt6 as named interval sets with the expected
// names when IPv6 is enabled.
func TestDOSExemptSetsCreatedAsInterval(t *testing.T) {
	boolFalse := false
	cfg := &FirewallConfig{
		DOSExemptRanges:             []string{"203.0.113.0/24"},
		DOSExemptKnownMailProviders: &boolFalse,
		IPv6:                        true,
	}
	conn, _ := nftConnReturningErrsThenOK(t)
	e := &Engine{cfg: cfg, conn: conn, statePath: t.TempDir()}
	e.table = conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})

	if err := e.createSets(); err != nil {
		t.Fatalf("createSets: %v", err)
	}

	if e.setDOSExempt == nil {
		t.Fatal("setDOSExempt is nil after createSets")
	}
	if !e.setDOSExempt.Interval {
		t.Error("setDOSExempt must be an interval set")
	}
	if e.setDOSExempt.Name != "dos_exempt_nets" {
		t.Errorf("setDOSExempt name = %q, want dos_exempt_nets", e.setDOSExempt.Name)
	}
	if e.setDOSExempt.KeyType != nftables.TypeIPAddr {
		t.Errorf("setDOSExempt KeyType = %v, want TypeIPAddr", e.setDOSExempt.KeyType)
	}

	if e.setDOSExempt6 == nil {
		t.Fatal("setDOSExempt6 is nil after createSets with IPv6=true")
	}
	if !e.setDOSExempt6.Interval {
		t.Error("setDOSExempt6 must be an interval set")
	}
	if e.setDOSExempt6.Name != "dos_exempt_nets6" {
		t.Errorf("setDOSExempt6 name = %q, want dos_exempt_nets6", e.setDOSExempt6.Name)
	}
	if e.setDOSExempt6.KeyType != nftables.TypeIP6Addr {
		t.Errorf("setDOSExempt6 KeyType = %v, want TypeIP6Addr", e.setDOSExempt6.KeyType)
	}
}

// TestDOSExemptSetsNotCreatedWithoutIPv6 verifies that setDOSExempt6 stays nil
// when IPv6 is disabled.
func TestDOSExemptSetsNotCreatedWithoutIPv6(t *testing.T) {
	boolFalse := false
	cfg := &FirewallConfig{
		DOSExemptRanges:             []string{"203.0.113.0/24"},
		DOSExemptKnownMailProviders: &boolFalse,
		IPv6:                        false,
	}
	conn, _ := nftConnReturningErrsThenOK(t)
	e := &Engine{cfg: cfg, conn: conn, statePath: t.TempDir()}
	e.table = conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})

	if err := e.createSets(); err != nil {
		t.Fatalf("createSets: %v", err)
	}

	if e.setDOSExempt == nil {
		t.Fatal("setDOSExempt should be created even when IPv6 is disabled")
	}
	if e.setDOSExempt6 != nil {
		t.Error("setDOSExempt6 must be nil when IPv6 is disabled")
	}
}

// TestDOSExemptIntervalElemsV4 verifies that dosExemptIntervalElems produces
// the correct interval pair for an IPv4 CIDR. Mirrors requireIntervalElems.
func TestDOSExemptIntervalElemsV4(t *testing.T) {
	_, n, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	elems := dosExemptIntervalElems([]*net.IPNet{n})
	requireIntervalElems(t, elems, "203.0.113.0/24")
}

// TestDOSExemptIntervalElemsV6 verifies that dosExemptIntervalElems produces
// the correct interval pair for an IPv6 CIDR.
func TestDOSExemptIntervalElemsV6(t *testing.T) {
	_, n, err := net.ParseCIDR("2001:db8::/32")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	elems := dosExemptIntervalElems([]*net.IPNet{n})
	// 2001:db8::/32 produces 2 elements: start + interval-end marker.
	if len(elems) != 2 {
		t.Fatalf("2001:db8::/32 elements = %d, want 2", len(elems))
	}
	wantStart := net.ParseIP("2001:db8::").To16()
	if !net.IP(elems[0].Key).Equal(wantStart) {
		t.Errorf("v6 start = %v, want %v", net.IP(elems[0].Key), wantStart)
	}
	if !elems[1].IntervalEnd {
		t.Error("second element must have IntervalEnd = true")
	}
}

// TestDOSExemptIntervalElemsEmpty verifies that dosExemptIntervalElems
// returns nil for an empty nets slice.
func TestDOSExemptIntervalElemsEmpty(t *testing.T) {
	if elems := dosExemptIntervalElems(nil); elems != nil {
		t.Errorf("empty nets should return nil, got %d elements", len(elems))
	}
}

// TestSetDOSExemptProviderNetsStores verifies that SetDOSExemptProviderNets
// stores nets and they are accessible to RefreshDOSExemptSets.
func TestSetDOSExemptProviderNetsStores(t *testing.T) {
	e := &Engine{cfg: &FirewallConfig{}}
	_, n4, _ := net.ParseCIDR("203.0.113.0/24")
	_, n6, _ := net.ParseCIDR("2001:db8::/32")
	nets := []*net.IPNet{n4, n6}

	e.SetDOSExemptProviderNets(nets)

	e.mu.Lock()
	got := e.dosExemptProviderNets
	e.mu.Unlock()
	if len(got) != len(nets) {
		t.Fatalf("provider nets len = %d, want %d", len(got), len(nets))
	}
}

// TestDOSExemptRefreshNilSetReturnsError verifies that RefreshDOSExemptSets
// returns an error when setDOSExempt is nil (not initialized).
func TestDOSExemptRefreshNilSetReturnsError(t *testing.T) {
	e := &Engine{
		cfg:       &FirewallConfig{},
		statePath: t.TempDir(),
		// setDOSExempt intentionally nil
	}
	err := e.RefreshDOSExemptSets(nil)
	if err == nil {
		t.Fatal("RefreshDOSExemptSets should error when setDOSExempt is nil")
	}
}

// TestDOSExemptApplyFailurePreservesPreviousSets verifies that when the kernel
// batch (Flush) fails, the engine's dosExemptProviderNets field retains the
// previous overlay and is not updated to the new value. This mirrors the
// rollback contract: a failed apply leaves the previous state active.
func TestDOSExemptApplyFailurePreservesPreviousSets(t *testing.T) {
	_, old4, _ := net.ParseCIDR("203.0.113.0/24")
	oldNets := []*net.IPNet{old4}

	_, new4, _ := net.ParseCIDR("198.51.100.0/24")
	newNets := []*net.IPNet{new4}

	table := dosExemptTestTable()
	setDOSExempt := &nftables.Set{
		Table: table, Name: "dos_exempt_nets",
		KeyType: nftables.TypeIPAddr, Interval: true,
	}
	setDOSExempt6 := &nftables.Set{
		Table: table, Name: "dos_exempt_nets6",
		KeyType: nftables.TypeIP6Addr, Interval: true,
	}

	conn := nftConnReturningErr(t, syscall.EPERM)
	e := &Engine{
		conn:                  conn,
		cfg:                   &FirewallConfig{IPv6: true},
		statePath:             t.TempDir(),
		setDOSExempt:          setDOSExempt,
		setDOSExempt6:         setDOSExempt6,
		dosExemptProviderNets: oldNets,
	}

	err := e.RefreshDOSExemptSets(newNets)
	if err == nil {
		t.Fatal("RefreshDOSExemptSets must return error when Flush fails")
	}

	e.mu.Lock()
	got := e.dosExemptProviderNets
	e.mu.Unlock()

	if len(got) != len(oldNets) {
		t.Fatalf("provider nets len = %d, want %d (old nets must be preserved)", len(got), len(oldNets))
	}
	if !got[0].IP.Equal(oldNets[0].IP) {
		t.Errorf("provider nets[0] = %v, want %v (old net must be preserved)", got[0], oldNets[0])
	}
}

// TestDOSExemptRefreshUpdatesOverlayOnSuccess verifies that
// RefreshDOSExemptSets updates dosExemptProviderNets when the kernel
// batch succeeds.
func TestDOSExemptRefreshUpdatesOverlayOnSuccess(t *testing.T) {
	_, old4, _ := net.ParseCIDR("203.0.113.0/24")
	oldNets := []*net.IPNet{old4}

	_, new4, _ := net.ParseCIDR("198.51.100.0/24")
	newNets := []*net.IPNet{new4}

	table := dosExemptTestTable()
	setDOSExempt := &nftables.Set{
		Table: table, Name: "dos_exempt_nets",
		KeyType: nftables.TypeIPAddr, Interval: true,
	}

	conn, _ := nftConnReturningErrsThenOK(t)
	e := &Engine{
		conn:                  conn,
		cfg:                   &FirewallConfig{IPv6: false},
		statePath:             t.TempDir(),
		setDOSExempt:          setDOSExempt,
		dosExemptProviderNets: oldNets,
	}

	if err := e.RefreshDOSExemptSets(newNets); err != nil {
		t.Fatalf("RefreshDOSExemptSets returned error: %v", err)
	}

	e.mu.Lock()
	got := e.dosExemptProviderNets
	e.mu.Unlock()

	if len(got) != len(newNets) {
		t.Fatalf("provider nets len = %d, want %d (new nets after success)", len(got), len(newNets))
	}
	if !got[0].IP.Equal(newNets[0].IP) {
		t.Errorf("provider nets[0] = %v, want %v", got[0], newNets[0])
	}
}
