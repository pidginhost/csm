package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

func TestDaemonReportsActualAttackEventQueue(t *testing.T) {
	previous := store.Global()
	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(sdb)
	t.Cleanup(func() { store.SetGlobal(previous); _ = sdb.Close() })
	d := New(&config.Config{StatePath: t.TempDir()}, nil, nil, "")
	if _, ok := d.QueueStatuses()["attackdb.events"]; ok {
		t.Fatal("uninitialized attack database published a queue")
	}
	db := attackdb.NewForTest(nil)
	d.prepareAttackDatabase(db)
	for i := 0; i < 3; i++ {
		db.RecordFinding(alert.Finding{Check: "wp_login_bruteforce", SourceIP: "198.51.100.23"})
	}
	if s, ok := d.QueueStatuses()["attackdb.events"]; !ok || s.Depth != 3 || s.InFlight != 0 || !s.CapacityUnavailable {
		t.Fatalf("actual event queue missing: found=%v status=%+v", ok, s)
	}
	if err := sdb.Close(); err != nil {
		t.Fatal(err)
	}
	db.Stop()
	s, ok := d.QueueStatuses()["attackdb.events"]
	if !ok || s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 3 || s.RecentDrops != 3 || s.Status != "degraded" {
		t.Fatalf("shutdown loss missing: found=%v status=%+v", ok, s)
	}
	if source := db.QueueStatuses(time.Now())["events"]; source != s {
		t.Fatalf("daemon and source rows differ: daemon=%+v source=%+v", s, source)
	}
}

func TestDaemonReportsActualAttackRecordQueue(t *testing.T) {
	previous := store.Global()
	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(sdb)
	t.Cleanup(func() { store.SetGlobal(previous); _ = sdb.Close() })
	d := New(&config.Config{StatePath: t.TempDir()}, nil, nil, "")
	if _, ok := d.QueueStatuses()["attackdb.records"]; ok {
		t.Fatal("uninitialized attack database published records")
	}
	db := attackdb.NewForTest(nil)
	d.prepareAttackDatabase(db)
	for i := 0; i < 3; i++ {
		db.RecordFinding(alert.Finding{Check: "wp_login_bruteforce", SourceIP: "198.51.100.23"})
	}
	db.RemoveIP("203.0.113.24")
	if s, ok := d.QueueStatuses()["attackdb.records"]; !ok || s.Depth != 2 || s.InFlight != 0 || s.DepthUnit != "records" || !s.CapacityUnavailable || s.DroppedTotal != 0 {
		t.Fatalf("actual coalesced queue missing: found=%v status=%+v", ok, s)
	}
	if err := sdb.Close(); err != nil {
		t.Fatal(err)
	}
	db.Stop()
	if s, ok := d.QueueStatuses()["attackdb.records"]; !ok || s.Depth != 2 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Reason != "retry_failed" {
		t.Fatalf("shutdown hid retained record retries: found=%v status=%+v", ok, s)
	}
}

// Events recorded before an address joined infra_ips keep it ranked as an
// attacker for the 90-day record lifetime unless startup drops them.
func TestPrepareAttackDatabaseForgetsInfraIPs(t *testing.T) {
	// Firewall protection and Cloudflare membership do not exempt recording.
	checks.SetCloudflareNets([]string{"192.0.2.0/24"})
	t.Cleanup(func() { checks.SetCloudflareNets(nil) })
	if !checks.IsInfraIP("192.0.2.10", nil) {
		t.Fatal("Cloudflare fixture is not protected")
	}
	previous := store.Global()
	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(sdb)
	t.Cleanup(func() { store.SetGlobal(previous); _ = sdb.Close() })
	d := New(&config.Config{
		StatePath: t.TempDir(),
		InfraIPs:  []string{"198.51.100.0/24", " 203.0.113.9 ", "infra.example.com"},
		Firewall:  &firewall.FirewallConfig{InfraIPs: []string{"203.0.113.10"}},
	}, nil, nil, "")
	db := attackdb.NewForTest(nil)
	t.Cleanup(db.Stop)
	for _, ip := range []string{"198.51.100.23", "203.0.113.9", "203.0.113.10", "192.0.2.10"} {
		db.RecordFinding(alert.Finding{Check: "ssh_login_unknown_ip", SourceIP: ip})
	}

	d.prepareAttackDatabase(db)

	for _, ip := range []string{"198.51.100.23", "203.0.113.9"} {
		if rec := db.LookupIP(ip); rec != nil {
			t.Errorf("infra address %s kept its attack record: %+v", ip, rec)
		}
	}
	for _, ip := range []string{"203.0.113.10", "192.0.2.10"} {
		if db.LookupIP(ip) == nil {
			t.Errorf("non-infra address %s lost its attack record", ip)
		}
	}
	if got := db.TotalIPs(); got != 2 {
		t.Fatalf("TotalIPs = %d, want 2", got)
	}
	persisted := sdb.LoadAllIPRecords()
	if len(persisted) != 2 || persisted["203.0.113.10"] == nil || persisted["192.0.2.10"] == nil {
		t.Fatalf("startup persisted the wrong records: %+v", persisted)
	}
}
