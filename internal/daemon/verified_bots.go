package daemon

import (
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/threatintel"
)

// verifiedBotEntries converts the operator-configured reputation.verified_bots
// list into the threatintel registry shape.
func verifiedBotEntries(cfg *config.Config) []threatintel.BotEntry {
	if cfg == nil {
		return nil
	}
	out := make([]threatintel.BotEntry, 0, len(cfg.Reputation.VerifiedBots))
	for _, b := range cfg.Reputation.VerifiedBots {
		out = append(out, threatintel.BotEntry{
			Name:         b.Name,
			UASubstrings: b.UASubstrings,
			RDNSSuffixes: b.RDNSSuffixes,
		})
	}
	return out
}

// reconcileVerifiedBots re-applies reputation.verified_bots after a SIGHUP so
// operators can add or change good bots without a restart. Re-stamping the
// PTR-verdict cache with the new list drops cached verdicts when the list
// changed, so a previously-spoofed IP is re-checked under the new suffixes
// instead of staying pinned for the cache TTL.
func (d *Daemon) reconcileVerifiedBots() {
	cfg := d.activeOrStartupCfg()
	entries := verifiedBotEntries(cfg)
	threatintel.SetOperatorBots(entries)
	if !cfg.BotVerifyEnabled() {
		return
	}
	db := store.Global()
	if db == nil {
		return
	}
	ver := threatintel.OperatorBotsCacheVersion(threatintel.LogicVersion, entries)
	if dropped, err := db.EnsureBotVerifyLogicVersion(ver); err == nil && dropped {
		csmlog.Info("bot-verify cache dropped after verified_bots change")
	}
	if d.botVerifier == nil {
		d.startBotVerifier(db, entries)
		return
	}
	d.botVerifier.SetOperatorEntries(entries)
}

func (d *Daemon) startBotVerifier(db *store.DB, entries []threatintel.BotEntry) {
	bv := threatintel.NewAsyncBotVerifier(db.PutBotVerify)
	bv.SetOperatorEntries(entries)
	d.botVerifier = bv
	d.wg.Add(1)
	obs.Go("bot-verify", func() {
		defer d.wg.Done()
		bv.Run(d.stopCh)
	})
	checks.SetBotVerifier(bv, db.GetBotVerify)
}
