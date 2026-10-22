//go:build linux && nftkernel

package store

import (
	"bytes"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/pidginhost/csm/internal/firewall"
)

// kernelElement returns the blocked-set element the kernel holds for ip.
func kernelElement(t *testing.T, ip string) (nftables.SetElement, bool) {
	t.Helper()
	parsed := net.ParseIP(ip)
	set, key := "blocked_ips", parsed.To4()
	if key == nil {
		set, key = "blocked_ips6", parsed.To16()
	}
	for _, elem := range kernelSetElements(t, set) {
		if bytes.Equal(elem.Key, key) {
			return elem, true
		}
	}
	return nftables.SetElement{}, false
}

func autoBlock(id, ip string, ttl time.Duration) firewall.ActionRequest {
	return firewall.ActionRequest{ID: id, Target: ip, Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: ttl}
}

// An automatic block at the temporary limit records the row it evicts, and
// its undo puts that row back with the expiry it had, in committed state and
// in the kernel.
func TestKernelDurableEvictionRecordsAndRestoresItsVictim(t *testing.T) {
	db, _, d := durableKernelEngine(t)
	for _, req := range []firewall.ActionRequest{autoBlock("soonest", "203.0.113.61", time.Hour), autoBlock("later", "203.0.113.62", 2*time.Hour)} {
		if out, err := d.BlockIPRequest(req, nil); err != nil || out != firewall.BlockOutcomeLive {
			t.Fatalf("%s = %s, %v", req.ID, out, err)
		}
	}
	before, _, err := db.ReadFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	var victim firewall.BlockedEntry
	for _, row := range before.Blocked {
		if row.IP == "203.0.113.61" {
			victim = row
		}
	}
	if out, blockErr := d.BlockIPRequest(autoBlock("evicting", "203.0.113.63", 3*time.Hour), nil); blockErr != nil || out != firewall.BlockOutcomeLive {
		t.Fatalf("evicting block = %s, %v", out, blockErr)
	}
	a, err := db.ReadFirewallAction("evicting")
	if err != nil || a.Phase != "verified" || len(a.Members) != 1 || !reflect.DeepEqual(a.Members[0].Victims, []firewall.BlockedEntry{victim}) {
		t.Fatalf("evicting action = %#v, %v", a.Members, err)
	}
	if _, live := kernelElement(t, victim.IP); live {
		t.Fatal("the victim is still in the kernel")
	}
	if _, err = d.UndoAction(firewall.ActionRequest{ID: "undo-evicting", Operation: "undo", Actor: "cli", Source: "cli", UndoOf: "evicting"}); err != nil {
		t.Fatal(err)
	}
	after, _, err := db.ReadFirewallState()
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("undo left %#v, %v; want %#v", after.Blocked, err, before.Blocked)
	}
	elem, live := kernelElement(t, victim.IP)
	if left := time.Until(victim.ExpiresAt); !live || elem.Expires > left+2*time.Second || elem.Expires < left-2*time.Second {
		t.Fatalf("restored victim element = %#v, %v; want %s left", elem, live, left)
	}
}
