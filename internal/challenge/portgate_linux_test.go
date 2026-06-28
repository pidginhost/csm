//go:build linux

package challenge

import (
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
)

// nftConnErr returns an nftables.Conn whose every netlink exchange fails with
// errno, so Flush surfaces that error to the caller under test.
func nftConnErr(t *testing.T, errno syscall.Errno) *nftables.Conn {
	t.Helper()
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		return nltest.Error(int(errno), req)
	}))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func newTestPortGate(conn *nftables.Conn) *linuxPortGate {
	tbl := &nftables.Table{Name: "csm_chal", Family: nftables.TableFamilyINet}
	return &linuxPortGate{
		conn:       conn,
		family:     portGateFamily{v4: true},
		setChalIPs: &nftables.Set{Table: tbl, Name: "chal_ips", KeyType: nftables.TypeIPAddr},
	}
}

// TestRevokeTreatsMissingElementAsSuccess locks the second layer of the
// port-gate ENOENT fix: gate elements carry a TTL and the kernel may auto-expire
// one before Revoke runs, so deleting an already-absent element (ENOENT) is a
// successful no-op, not an error worth logging.
func TestRevokeTreatsMissingElementAsSuccess(t *testing.T) {
	g := newTestPortGate(nftConnErr(t, syscall.ENOENT))
	if err := g.Revoke("203.0.113.5"); err != nil {
		t.Fatalf("Revoke must treat a missing element (ENOENT) as success, got: %v", err)
	}
}

// TestRevokeSurfacesRealErrors ensures only ENOENT is swallowed; other netlink
// failures still propagate so genuine problems are not hidden.
func TestRevokeSurfacesRealErrors(t *testing.T) {
	g := newTestPortGate(nftConnErr(t, syscall.EPERM))
	if err := g.Revoke("203.0.113.5"); err == nil {
		t.Fatal("Revoke must surface non-ENOENT netlink errors")
	}
}
