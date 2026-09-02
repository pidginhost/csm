package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// A reload that adds an IP to reputation.whitelist must stop the threat
// database from flagging it; the field is hot-reloadable and the reload
// reported success while lookups kept the startup list.
func TestReconcileReputationWhitelistAppliesReloadedList(t *testing.T) {
	prevActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prevActive) })
	restore := checks.SetGlobalThreatDBForTest(t.TempDir())
	t.Cleanup(restore)

	db := checks.GetThreatDB()
	db.AddPermanent("203.0.113.44", "test-feed")

	startup := &config.Config{}
	d := New(startup, nil, nil, "")
	t.Cleanup(func() {
		close(d.stopCh)
		d.wg.Wait()
	})

	reloaded := &config.Config{}
	reloaded.Reputation.Whitelist = []string{"203.0.113.44"}
	config.SetActive(reloaded)
	d.reconcileReputationWhitelist()

	if _, found := db.Lookup("203.0.113.44"); found {
		t.Fatal("IP added to reputation.whitelist by reload is still flagged by the threat database")
	}
}
