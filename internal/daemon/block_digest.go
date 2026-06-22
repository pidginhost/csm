package daemon

import (
	"fmt"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
)

var (
	blockDigestSendEmail       = alert.SendEmail
	blockDigestSendWebhookJSON = alert.SendWebhookJSON
)

// buildBlockDigest constructs the collector from config, or returns nil when
// the feature is disabled. Built once at startup; block_digest is
// hotreload:"restart" so its settings do not change under a live daemon.
func (d *Daemon) buildBlockDigest(cfg *config.Config) *blockdigest.Collector {
	if !cfg.Alerts.BlockDigest.Enabled {
		return nil
	}
	configuredCountries := blockdigest.ResolveCountries(cfg.Alerts.BlockDigest.Countries, nil)
	countries := blockdigest.ResolveCountries(cfg.Alerts.BlockDigest.Countries, cfg.Suppressions.TrustedCountries)
	if len(countries) == 0 {
		csmlog.Warn("block_digest enabled with no countries; watching ALL countries (set alerts.block_digest.countries or suppressions.trusted_countries)")
	}
	var countriesOf func() []string
	if len(configuredCountries) == 0 {
		countriesOf = func() []string {
			live := d.currentCfg()
			if live == nil {
				live = cfg
			}
			return blockdigest.ResolveCountries(nil, live.Suppressions.TrustedCountries)
		}
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
		CountriesOf: countriesOf,
		CountryOf:   d.countryOf,
		EmailSink:   email,
		WebhookSink: webhook,
		OnError: func(channel string, err error) {
			csmlog.Warn("block_digest delivery failed", "channel", channel, "err", err)
		},
	})
}

// blockDigestSinks selects delivery: an empty channel follows whichever alerts
// channels are enabled; an explicit channel forces just that one.
func (d *Daemon) blockDigestSinks(cfg *config.Config) (func(subject, body string) error, func(blockdigest.WebhookPayload) error) {
	ch := cfg.Alerts.BlockDigest.Channel
	currentCfg := func() *config.Config {
		if live := d.currentCfg(); live != nil {
			return live
		}
		return cfg
	}

	emailSink := func(requireEnabled bool) func(subject, body string) error {
		return func(subject, body string) error {
			live := currentCfg()
			if !live.Alerts.Email.Enabled {
				if requireEnabled {
					return fmt.Errorf("email alerts disabled")
				}
				return nil
			}
			return blockDigestSendEmail(live, subject, body)
		}
	}
	webhookSink := func(requireEnabled bool) func(blockdigest.WebhookPayload) error {
		return func(p blockdigest.WebhookPayload) error {
			live := currentCfg()
			if !live.Alerts.Webhook.Enabled {
				if requireEnabled {
					return fmt.Errorf("webhook alerts disabled")
				}
				return nil
			}
			return blockDigestSendWebhookJSON(live, p)
		}
	}

	switch ch {
	case "":
		return emailSink(false), webhookSink(false)
	case "email":
		return emailSink(true), nil
	case "webhook":
		return nil, webhookSink(true)
	default:
		return nil, nil
	}
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
