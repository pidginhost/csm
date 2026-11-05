package daemon

import (
	"fmt"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/store"
)

var (
	blockDigestSendEmail       = alert.SendEmail
	blockDigestSendWebhookJSON = alert.SendWebhookJSON
)

// buildBlockDigest constructs the collector that sends the daily alert
// summary; with block_digest enabled it also watches blocks by country. Built
// once at startup; block_digest is hotreload:"restart" so its settings do not
// change under a live daemon.
func (d *Daemon) buildBlockDigest(cfg *config.Config) *blockdigest.Collector {
	watch := cfg.Alerts.BlockDigest.Enabled
	configuredCountries := blockdigest.ResolveCountries(cfg.Alerts.BlockDigest.Countries, nil)
	countries := blockdigest.ResolveCountries(cfg.Alerts.BlockDigest.Countries, cfg.Suppressions.TrustedCountries)
	if watch && len(countries) == 0 {
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
	collector := blockdigest.New(blockdigest.Options{
		Watch:        watch,
		Countries:    countries,
		SendOn:       cfg.Alerts.BlockDigest.SendOn,
		Interval:     cfg.BlockDigestInterval(),
		Live:         cfg.Alerts.BlockDigest.Live,
		LiveChannel:  cfg.Alerts.BlockDigest.Channel,
		MinBlock:     cfg.Alerts.BlockDigest.MinBlock,
		Host:         cfg.Hostname,
		Version:      d.version,
		CountriesOf:  countriesOf,
		CountryOf:    d.countryOf,
		EnrichModSec: d.modsecEnricher(cfg),
		EmailSink:    email,
		WebhookSink:  webhook,
		LoadSummary: func() ([]byte, error) {
			if db := store.Global(); db != nil {
				return db.LoadDailySummary()
			}
			return nil, nil
		},
		SaveSummary: func(b []byte) error {
			if db := store.Global(); db != nil {
				return db.SaveDailySummary(b)
			}
			return nil
		},
		OnError: func(channel string, err error) {
			if channel == "summary" {
				csmlog.Warn("daily summary state not loaded or saved", "err", err)
				return
			}
			csmlog.Warn("block_digest delivery failed", "channel", channel, "err", err)
		},
		DeliveryEnabled: func(channel string) bool {
			live := d.currentCfg()
			if live == nil {
				live = cfg
			}
			if channel == "email" {
				return live.Alerts.Email.Enabled
			}
			return live.Alerts.Webhook.Enabled
		},
	})
	d.registerQueueSource("block_digest", collector)
	return collector
}

// blockDigestSinks builds both destinations for the daily summary. The
// collector applies block_digest.channel only to live block alerts.
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
			// The phpanel endpoint takes signed findings, not CSM's own
			// summary notifications.
			if live.Alerts.Webhook.Type == "phpanel" && p.CSM.Event == "daily_summary" {
				return nil
			}
			return blockDigestSendWebhookJSON(live, p)
		}
	}

	return emailSink(ch == "email"), webhookSink(ch == "webhook")
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

// appliedBlockReason returns the reason of an applied auto-block finding, or
// "" for any other finding. PERMBLOCK promotions carry no reason.
func appliedBlockReason(f alert.Finding) string {
	if f.Check != "auto_block" || f.Severity != alert.Critical {
		return ""
	}
	reason := strings.TrimPrefix(f.Details, "Reason: ")
	return strings.TrimSuffix(reason, " (warning: "+firewall.CloudflareCoverageWarning+")")
}

// observeBlocks feeds real auto-block findings to the digest collector.
// PERMBLOCK promotions (no reason details) and non-auto_block findings are
// skipped; dedup-by-IP in the collector makes multiple call sites safe.
func (d *Daemon) observeBlocks(actions []alert.Finding) {
	if d.blockDigest == nil {
		return
	}
	for _, f := range actions {
		reason := appliedBlockReason(f)
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

// noteSummary is the alert summary hook: it counts the summary-class findings
// of one dispatch for the daily summary. It runs inside dispatch, so it never
// panics into it.
func (d *Daemon) noteSummary(cfg *config.Config, summary []alert.Finding) {
	collector := d.blockDigest
	if collector == nil || len(summary) == 0 {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			csmlog.Warn("daily summary dropped findings", "panic", r)
		}
	}()
	muted := make(map[string]bool, len(cfg.Alerts.Email.DisabledChecks))
	for _, name := range cfg.Alerts.Email.DisabledChecks {
		muted[config.CanonicalCheckName(strings.TrimSpace(name))] = true
	}
	batch := make([]blockdigest.Handled, 0, len(summary))
	for _, f := range summary {
		batch = append(batch, blockdigest.Handled{
			Check:       f.Check,
			Severity:    f.Severity.String(),
			IP:          checks.ExtractIPFromFinding(f),
			BlockReason: appliedBlockReason(f),
			Muted:       muted[config.CanonicalCheckName(f.Check)],
		})
	}
	collector.NoteHandled(batch)
}
