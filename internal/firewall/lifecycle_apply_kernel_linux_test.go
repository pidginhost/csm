//go:build linux && nftkernel

package firewall

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/nftables"
)

func TestKernelDurableBulkRemoval(t *testing.T) {
	isolatedFirewallNamespace(t)
	conn, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	e := deltaTestEngine(t, conn)
	table := conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})
	e.setBlocked6 = &nftables.Set{Name: "blocked_ips6", Table: table, KeyType: nftables.TypeIP6Addr}
	if err := conn.AddSet(e.setBlocked6, nil); err != nil {
		t.Fatal(err)
	}
	a := bulkRemovalAction()
	if err := addElementsChunked(conn, e.setBlocked6, actionElements(a.KernelBefore[0].Elements, time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := (engineActionKernel{e}).ApplyFirewallAction(a); err != nil {
		t.Fatal(err)
	}
	elements, err := conn.GetSetElements(e.setBlocked6)
	if err != nil {
		t.Fatal(err)
	}
	if len(elements) != 1 || !bytes.Equal(elements[0].Key, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("bulk removal left unexpected kernel elements: %d", len(elements))
	}
}
