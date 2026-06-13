package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/threatintel"
)

func TestReconcileVerifiedBotsStartsVerifierWhenReloadEnablesIt(t *testing.T) {
	prevActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prevActive) })

	prevStore := store.Global()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prevStore)
		_ = db.Close()
		threatintel.SetOperatorBots(nil)
	})

	startup := &config.Config{}
	startup.Reputation.BotVerifyEnabled = boolPtr(false)
	d := New(startup, nil, nil, "")
	t.Cleanup(func() {
		close(d.stopCh)
		d.wg.Wait()
	})

	reloaded := &config.Config{}
	reloaded.Reputation.BotVerifyEnabled = boolPtr(true)
	reloaded.Reputation.VerifiedBots = []config.VerifiedBot{{
		Name:         "acmebot",
		UASubstrings: []string{"acmecrawler"},
		RDNSSuffixes: []string{"acme.example"},
	}}
	config.SetActive(reloaded)

	d.reconcileVerifiedBots()
	if d.botVerifier == nil {
		t.Fatal("reconcileVerifiedBots did not start verifier after bot verification was enabled")
	}
	if got := threatintel.ClaimedBotFromUA("AcmeCrawler/1.0"); got != "acmebot" {
		t.Fatalf("operator bot registry = %q, want acmebot", got)
	}
}
