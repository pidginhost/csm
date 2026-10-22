//go:build linux && nftkernel

package store

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

// A batch the kernel holds only part of stays unknown and holds every
// mutation until its members expire; then recovery in a restarted engine
// retires it, and mutations proceed.
func TestKernelDurableUnknownBatchRetiresAfterExpiry(t *testing.T) {
	db, e, d := durableKernelEngine(t)
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	calls := 0
	boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		calls++
		if calls == 3 {
			return errors.New("crash before the applied outcome")
		}
		return previous(b, fn)
	}
	header := firewall.ActionRequest{ID: "batch-retire", Operation: "block", Actor: "auto", Source: "scan", Automatic: true}
	short := func(id, ip string) firewall.ActionRequest {
		m := kernelBatchMember(id, ip)
		m.TTL = 3 * time.Second
		return m
	}
	if _, err := e.BlockBatchRequest(header, []firewall.ActionRequest{short("member-a", "203.0.113.80"), short("member-b", "203.0.113.81")}, nil); !errors.Is(err, firewall.ErrActionUnknown) {
		t.Fatalf("interrupted batch = %v", err)
	}
	boltUpdate = previous
	// Take one member's element out: the kernel now proves neither state.
	conn := &nftables.Conn{}
	set, err := conn.GetSetByName(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet}, "blocked_ips")
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.SetDeleteElements(set, []nftables.SetElement{{Key: net.ParseIP("203.0.113.80").To4()}}); err != nil {
		t.Fatal(err)
	}
	if err = conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if err = d.RecoverActions(); !errors.Is(err, firewall.ErrActionUnknown) {
		t.Fatalf("recovery while a member is live = %v", err)
	}
	if _, err = d.BlockIPRequest(autoBlock("held", "203.0.113.82", time.Hour), nil); !errors.Is(err, firewall.ErrActionUnknown) {
		t.Fatalf("mutation while unknown = %v", err)
	}
	stored, err := db.ReadFirewallAction(header.ID)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(stored.CreatedAt.Add(3*time.Second + 1500*time.Millisecond)))

	restarted, err := firewall.NewEngine(&firewall.FirewallConfig{Enabled: true, IPv6: true, DenyTempIPLimit: 2}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var audited []firewall.FirewallAction
	if err = restarted.AttachLifecycle(&firewall.Lifecycle{Store: db, RetirementClockTrusted: func() (bool, error) { return true, nil }, Audit: func(a firewall.FirewallAction) error { audited = append(audited, a); return nil }}); err != nil {
		t.Fatal(err)
	}
	if err = restarted.RecoverActions(); err != nil {
		t.Fatalf("recovery after expiry = %v", err)
	}
	retired, err := db.ReadFirewallAction(header.ID)
	if err != nil || !retired.Retired || retired.Phase != "unknown" || len(audited) == 0 || !audited[len(audited)-1].Retired {
		t.Fatalf("retired = %#v, %v; audited %d", retired, err, len(audited))
	}
	state, _, err := db.ReadFirewallState()
	if err != nil || !reflect.DeepEqual(state, stored.Before) {
		t.Fatalf("state after retirement = %#v, %v; want %#v", state, err, stored.Before)
	}
	if err := restarted.Apply(); err != nil {
		t.Fatal(err)
	}
	if out, err := restarted.BlockIPRequest(autoBlock("after", "203.0.113.82", time.Hour), nil); err != nil || out != firewall.BlockOutcomeLive {
		t.Fatalf("block after retirement = %s, %v", out, err)
	}
}
