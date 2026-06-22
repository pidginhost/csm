package daemon

import (
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// buildBlockDigest constructs the collector from config, or returns nil when
// the feature is disabled. Built once at startup; block_digest is
// hotreload:"restart" so its settings do not change under a live daemon.
func (d *Daemon) buildBlockDigest(cfg *config.Config) *blockdigest.Collector {
	if !cfg.Alerts.BlockDigest.Enabled {
		return nil
	}
	countries := blockdigest.ResolveCountries(cfg.Alerts.BlockDigest.Countries, cfg.Suppressions.TrustedCountries)
	if len(countries) == 0 {
		csmlog.Warn("block_digest enabled with no countries; watching ALL countries (set alerts.block_digest.countries or suppressions.trusted_countries)")
	}
	email, webhook := d.blockDigestSinks(cfg)
	return blockdigest.New(blockdigest.Options{
		Countries:   countries,
		SendOn:      cfg.Alerts.BlockDigest.SendOn,
		Interval:    cfg.BlockDigestInterval(),
		Live:        cfg.Alerts.BlockDigest.Live,
		MinBlock:    cfg.Alerts.BlockDigest.MinBlock,
		Host:        cfg.Hostname,
		Version:     d.version,
		CountryOf:   d.countryOf,
		EmailSink:   email,
		WebhookSink: webhook,
	})
}

// blockDigestSinks selects delivery: an empty channel follows whichever alerts
// channels are enabled; an explicit channel forces just that one.
func (d *Daemon) blockDigestSinks(cfg *config.Config) (func(subject, body string) error, func(blockdigest.WebhookPayload) error) {
	ch := cfg.Alerts.BlockDigest.Channel
	wantEmail := (ch == "" && cfg.Alerts.Email.Enabled) || ch == "email"
	wantWebhook := (ch == "" && cfg.Alerts.Webhook.Enabled) || ch == "webhook"

	var email func(subject, body string) error
	var webhook func(blockdigest.WebhookPayload) error
	if wantEmail {
		email = func(subject, body string) error { return alert.SendEmail(cfg, subject, body) }
	}
	if wantWebhook {
		webhook = func(p blockdigest.WebhookPayload) error { return alert.SendWebhookJSON(cfg, p) }
	}
	return email, webhook
}

// countryOf resolves an IP to its ISO country via the loaded GeoIP mmdb. It
// reads through the atomic accessor so it never races the geoip hot-reload swap.
func (d *Daemon) countryOf(ip string) string {
	db := getGeoIPDB()
	if db == nil {
		return ""
	}
	return db.Lookup(ip).Country
}

// observeBlocks feeds real auto-block findings to the digest collector.
// PERMBLOCK promotions (no reason details) and non-auto_block findings are
// skipped; dedup-by-IP in the collector makes multiple call sites safe.
func (d *Daemon) observeBlocks(actions []alert.Finding) {
	if d.blockDigest == nil {
		return
	}
	for _, f := range actions {
		if f.Check != "auto_block" || f.Severity != alert.Critical {
			continue
		}
		reason := strings.TrimPrefix(f.Details, "Reason: ")
		if reason == "" {
			continue
		}
		ip := checks.ExtractIPFromFinding(f)
		if ip == "" {
			continue
		}
		d.blockDigest.Observe(ip, reason, f.Timestamp)
	}
}
