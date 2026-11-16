//go:build linux && nftkernel

package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/google/nftables"

	"github.com/pidginhost/csm/internal/firewall"
)

// kernelBlockedElement is the blocked_ips element of ip in the engine's
// table, read over its own connection.
func kernelBlockedElement(t *testing.T, conn *nftables.Conn, ip string) (*nftables.Set, nftables.SetElement, bool) {
	t.Helper()
	set, err := conn.GetSetByName(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet}, "blocked_ips")
	if err != nil {
		t.Fatal(err)
	}
	elements, err := conn.GetSetElements(set)
	if err != nil {
		t.Fatal(err)
	}
	for _, el := range elements {
		if net.IP(el.Key).String() == ip {
			return set, el, true
		}
	}
	return set, nftables.SetElement{}, false
}

// The engine the firewall started is the one a rollback retimes: a
// temporary block whose element came back with a stale timer is on its
// row's time again when the window has rolled back.
func TestKernelRolledBackWindowRetimesTheStartedEngine(t *testing.T) {
	isolatedNetns(t)
	const ip = "203.0.113.75"
	unproven := false
	d, _, _ := gatedFirewall(t, &unproven)
	d.startFirewallUsing(firewallStartupOps{
		newEngine:  firewall.NewEngine,
		apply:      (*firewall.Engine).Apply,
		unproven:   func([]string) ([]string, error) { return nil, nil },
		settled:    func([]string) ([]string, error) { return nil, nil },
		leaseFloor: func() (time.Time, error) { return time.Time{}, nil },
	})
	if d.fwEngine == nil {
		t.Fatal("the firewall did not start")
	}
	if err := d.fwEngine.BlockIPForce(ip, "operator", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	confirmFile, rollbackFile, legacyRollbackFile := firewallRollbackFiles(d.cfg.StatePath)
	if err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Hour, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	// The fixture's nft restores nothing, so give the element the timer a
	// restored dump would.
	conn, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	set, el, held := kernelBlockedElement(t, conn, ip)
	if !held {
		t.Fatal("the temporary block has no element")
	}
	if err = conn.SetDeleteElements(set, []nftables.SetElement{{Key: el.Key}}); err != nil {
		t.Fatal(err)
	}
	if err = conn.SetAddElements(set, []nftables.SetElement{{Key: el.Key, Timeout: 2 * time.Hour}}); err != nil {
		t.Fatal(err)
	}
	if err = conn.Flush(); err != nil {
		t.Fatal(err)
	}
	marker := mustRead(t, confirmFile)
	firewallDeadmanMu.Lock()
	err = restoreFirewallRollback(confirmFile, rollbackFile, marker)
	firewallDeadmanMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	_, el, held = kernelBlockedElement(t, conn, ip)
	if !held || el.Expires <= 29*time.Minute || el.Expires > 30*time.Minute {
		t.Fatalf("the temporary block after the rollback = %+v, held %v; want its row's 30 minutes", el, held)
	}
}
