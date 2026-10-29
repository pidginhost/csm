package attackdb

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/netutil"
	"github.com/pidginhost/csm/internal/store"
)

func TestForgetNetworksPersistsAliasesAndRetainsEvents(t *testing.T) {
	for _, backend := range []string{"file", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			db := eventQueueFlatDB(t)
			if backend == "bbolt" {
				_, cleanup := setupBboltStore(t)
				t.Cleanup(cleanup)
			}
			seedRoot := t.TempDir()
			seedDir := filepath.Join(seedRoot, "threat_db")
			if err := os.Mkdir(seedDir, 0700); err != nil {
				t.Fatal(err)
			}
			seed := "192.0.2.5\n::ffff:192.0.2.5\n2001:db8::5\n2001:0db8:0:0:0:0:0:5\n203.0.113.9\n"
			if err := os.WriteFile(filepath.Join(seedDir, "permanent.txt"), []byte(seed), 0600); err != nil {
				t.Fatal(err)
			}
			if got := db.SeedFromPermanentBlocklist(seedRoot); got != 5 {
				t.Fatalf("seeded %d records, want 5", got)
			}
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}
			before := make(map[string][]Event)
			for _, ip := range strings.Fields(seed) {
				before[ip] = db.QueryEvents(ip, 10)
				if len(before[ip]) != 1 || before[ip][0].IP != ip {
					t.Fatalf("missing imported event for %s: %+v", ip, before[ip])
				}
			}
			if got := db.ForgetNetworks(nil); got != 0 || db.TotalIPs() != 5 {
				t.Fatal("empty networks changed records")
			}
			nets := []*net.IPNet{
				netutil.ParseCIDROrIP("192.0.2.0/24"),
				netutil.ParseCIDROrIP("192.0.2.5"),
				netutil.ParseCIDROrIP("2001:db8::/32"),
			}
			if got := db.ForgetNetworks(nets); got != 4 {
				t.Fatalf("removed %d records, want 4", got)
			}
			if db.TotalIPs() != 1 || db.LookupIP("203.0.113.9") == nil {
				t.Fatalf("cleanup did not preserve exactly the unrelated record: %+v", db.AllRecords())
			}
			if got := db.ForgetNetworks(nets); got != 0 {
				t.Fatalf("repeated cleanup removed %d records", got)
			}
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}
			restored := NewForTest(nil)
			restored.dbPath = db.dbPath
			restored.load()
			if restored.TotalIPs() != 1 || restored.LookupIP("203.0.113.9") == nil {
				t.Fatalf("cleanup was not persisted: %+v", restored.AllRecords())
			}
			for ip, events := range before {
				if after := db.QueryEvents(ip, 10); !slices.Equal(events, after) {
					t.Fatalf("cleanup changed event history for %s: before=%+v after=%+v", ip, events, after)
				}
			}
		})
	}
}

func TestForgetNetworksRetriesFailedDeletion(t *testing.T) {
	_, cleanup := setupBboltStore(t)
	t.Cleanup(cleanup)
	db := NewForTest(nil)
	db.RecordFinding(findingFromIP("192.0.2.5"))
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := db.ForgetNetworks([]*net.IPNet{netutil.ParseCIDROrIP("192.0.2.0/24")}); got != 1 {
		t.Fatalf("removed %d records, want 1", got)
	}
	db.deleteRecord = func(*store.DB, string) error { return errors.New("delete unavailable") }
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 1 || s.Reason != "retry_failed" {
		t.Fatalf("failed deletion was not retained for retry: %+v", s)
	}
	if len(store.Global().LoadAllIPRecords()) != 1 {
		t.Fatal("failed deletion changed persisted records")
	}
	db.deleteRecord = nil
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(store.Global().LoadAllIPRecords()) != 0 {
		t.Fatal("retry retained deleted records")
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.Status != "ok" {
		t.Fatalf("successful deletion left pending work: %+v", s)
	}
}
