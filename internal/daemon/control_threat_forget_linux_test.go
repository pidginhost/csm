//go:build linux

package daemon

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

func TestHandleThreatForgetPreservesEnforcement(t *testing.T) {
	const blocked = "198.51.100.23"
	const allowed = "203.0.113.23"
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	previous := store.Global()
	store.SetGlobal(sdb)
	t.Cleanup(func() { store.SetGlobal(previous); _ = sdb.Close() })
	t.Cleanup(checks.SetGlobalThreatDBForTest(dir))
	tdb := checks.GetThreatDB()
	tdb.AddPermanent(blocked, "operator block")
	tdb.AddWhitelist(allowed)

	engine, err := firewall.NewEngine(&firewall.FirewallConfig{Enabled: true}, dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "firewall", "state.json")
	want := []byte(`{"blocked":[{"ip":"198.51.100.23","reason":"operator block"}],"allowed":[{"ip":"203.0.113.23","reason":"operator allow"}]}`)
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	if !engine.IsBlocked(blocked) || !engine.IsAllowed(allowed) || !sdb.IsWhitelisted(allowed) {
		t.Fatal("enforcement state was not seeded")
	}
	c := newListenerForTest(t)
	c.d.fwEngine = engine
	for _, ip := range []string{blocked, allowed} {
		seedAttackRecord(t, ip)
		if _, err := c.handleThreatForget([]byte(`{"ip":"` + ip + `"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if !engine.IsBlocked(blocked) || !engine.IsAllowed(allowed) {
		t.Fatal("forget changed firewall enforcement")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("forget changed saved firewall state: %s, %v", got, err)
	}
	if _, found := sdb.GetPermanentBlock(blocked); !found {
		t.Fatal("forget removed a permanent threat block")
	}
	if _, found := tdb.Lookup(blocked); !found {
		t.Fatal("forget exempted a blocked address from threat detection")
	}
	if !sdb.IsWhitelisted(allowed) || sdb.IsWhitelisted(blocked) {
		t.Fatal("forget changed the whitelist")
	}
}
