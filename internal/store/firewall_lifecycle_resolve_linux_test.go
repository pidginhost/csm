//go:build linux

package store

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

func TestFirewallResolveReportsCacheRefreshFailure(t *testing.T) {
	db := openSnapshotDB(t)
	l := resolverFor(t, db, func(firewall.FirewallAction) error { return nil })
	a, _ := strandedAction(t, db, l)
	s := &changingPlanningStore{DB: db}
	e, err := firewall.NewEngine(&firewall.FirewallConfig{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = e.AttachLifecycle(&firewall.Lifecycle{Store: s, Audit: func(firewall.FirewallAction) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("committed state unreadable")
	s.onRead = func(firewall.FirewallState, uint64) error { return failure }
	resolved, err := e.ResolveAction(a.Request.ID, "verified", "operator cli")
	if !errors.Is(err, failure) {
		t.Fatalf("resolution hid cache refresh failure: phase=%s err=%v", resolved.Phase, err)
	}
	if resolved.Phase != "verified" {
		t.Fatalf("persisted outcome lost: %s", resolved.Phase)
	}
	if errors.Is(err, firewall.ErrActionAuditPending) {
		t.Fatal("cache refresh failure misreported as pending audit")
	}
	assertFirewallSnapshot(t, db, a.After, 2)
}
