package daemon

import (
	"fmt"
	"net/netip"
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
		DeliveryEnabled: func(event, channel string) bool {
			live := d.currentCfg()
			if live == nil {
				live = cfg
			}
			if channel == "email" {
				return live.Alerts.Email.Enabled
			}
			return live.Alerts.Webhook.Enabled && !phpanelSkips(live, event)
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
			// Delivery policy already skips these; a reload to phpanel
			// between that check and this send must not post one either.
			if phpanelSkips(live, p.CSM.Event) {
				return nil
			}
			return blockDigestSendWebhookJSON(live, p)
		}
	}

	return emailSink(ch == "email"), webhookSink(ch == "webhook")
}

// phpanelSkips reports a collector event a phpanel webhook must not receive:
// that endpoint takes signed findings, not CSM's own summary notifications.
func phpanelSkips(cfg *config.Config, event string) bool {
	if cfg.Alerts.Webhook.Type != "phpanel" {
		return false
	}
	switch event {
	case "daily_summary", "customer_block":
		return true
	}
	return false
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
	return detailsReason(f)
}

// detailsReason is the reason an auto_block notice's details give, without
// the Cloudflare coverage warning.
func detailsReason(f alert.Finding) string {
	reason := strings.TrimPrefix(f.Details, "Reason: ")
	return strings.TrimSuffix(reason, " (warning: "+firewall.CloudflareCoverageWarning+")")
}

// summaryBlockReason is what the daily summary groups an applied block by.
// Netblock and permanent-block notices carry no reason; their message names
// the kind.
func summaryBlockReason(f alert.Finding) string {
	if reason := appliedBlockReason(f); reason != "" {
		return reason
	}
	if f.Check == "auto_block" && f.Severity == alert.Critical {
		return f.Message
	}
	return ""
}

// observeBlocks feeds real auto-block findings to the digest collector,
// then sends one alert naming those that hit known customers. PERMBLOCK
// promotions (no reason details) and non-auto_block findings are skipped by
// the digest; dedup-by-IP in the collector makes multiple call sites safe.
// Each applied block reaches it once, so it alerts once per block.
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
	d.blockDigest.AlertCustomerBlocks(d.customerBlocks(actions))
}

// maxCustomerExamples is how many known customers one subnet block names.
const maxCustomerExamples = 5

// blockTarget returns the kind of an auto_block notice (AUTO-BLOCK,
// AUTO-PERMBLOCK, AUTO-BLOCK-SUBNET or AUTO-NETBLOCK), the address or
// network it names, and whether it is a dry-run verdict, which puts
// "[dry-run]" after the kind.
func blockTarget(f alert.Finding) (kind, target string, dryRun bool) {
	fields := strings.Fields(f.Message)
	switch {
	case len(fields) >= 3 && fields[1] == "[dry-run]:":
		kind, target, dryRun = fields[0], fields[2], true
	case len(fields) >= 2 && strings.HasSuffix(fields[0], ":"):
		kind, target = strings.TrimSuffix(fields[0], ":"), fields[1]
	default:
		return "", "", false
	}
	switch kind {
	case "AUTO-BLOCK", "AUTO-PERMBLOCK":
		return kind, checks.ExtractIPFromFinding(f), dryRun
	case "AUTO-BLOCK-SUBNET", "AUTO-NETBLOCK":
		return kind, target, dryRun
	}
	return "", "", false
}

// customersAt returns the known customers target covers: an address's own
// last login, or the count and the most recent few inside a network.
func (d *Daemon) customersAt(target string) (blockdigest.CustomerBlock, bool) {
	if p, err := netip.ParsePrefix(target); err == nil {
		// The set keys IPv4 customers unmapped.
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		p = p.Masked()
		n, sample := d.knownCustomers.Within(p, maxCustomerExamples)
		return blockdigest.CustomerBlock{Target: p.String(), Hits: sample, More: n - len(sample)}, n > 0
	}
	hit, ok := d.knownCustomers.Lookup(target)
	return blockdigest.CustomerBlock{Target: target, Hits: []blockdigest.CustomerHit{hit}}, ok
}

// customerBlock fills in the reason and check of a block notice that hit
// known customers. Netblock and permanent-block notices carry no reason;
// their message says what happened.
func (d *Daemon) customerBlock(f alert.Finding, target string) (blockdigest.CustomerBlock, bool) {
	b, ok := d.customersAt(target)
	if !ok {
		return b, false
	}
	b.Reason = detailsReason(f)
	if b.Reason == "" {
		b.Reason = f.Message
	}
	if f.Cause != nil {
		b.Check = f.Cause.Check
	}
	return b, true
}

// customerBlocks returns the applied automatic blocks in actions that hit
// known customers. A permanent promotion joins the block of its address from
// the same batch, which the chokepoint emits first.
func (d *Daemon) customerBlocks(actions []alert.Finding) []blockdigest.CustomerBlock {
	var blocks []blockdigest.CustomerBlock
	byTarget := make(map[string]int)
	for _, f := range actions {
		if f.Check != "auto_block" || f.Severity != alert.Critical {
			continue
		}
		kind, target, _ := blockTarget(f)
		if i, ok := byTarget[target]; ok && kind == "AUTO-PERMBLOCK" {
			blocks[i].Reason += " (promoted to permanent block)"
			continue
		}
		b, ok := d.customerBlock(f, target)
		if !ok {
			continue
		}
		byTarget[target] = len(blocks)
		blocks = append(blocks, b)
	}
	return blocks
}

// wouldBlock returns the verdict in a summary finding that would have
// blocked known customers: a dry-run auto_block notice, or a spray verdict
// in observe mode. The established-source advisory of the same check is
// not a verdict.
func (d *Daemon) wouldBlock(check string, f alert.Finding) (blockdigest.CustomerBlock, bool) {
	switch {
	case check == "auto_block":
		if _, target, dryRun := blockTarget(f); dryRun {
			return d.customerBlock(f, target)
		}
	case check == "mail_bruteforce_suspected" && strings.Contains(f.Message, "(observe mode, not blocked)"):
		b, ok := d.customersAt(f.SourceIP)
		b.Reason, b.Check = f.Message, check
		return b, ok
	}
	return blockdigest.CustomerBlock{}, false
}

// noteSummary is the alert summary hook: it counts the summary-class findings
// of one dispatch for the daily summary and lists the verdicts that would
// have blocked known customers. It runs inside dispatch, so it never panics
// into it.
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
		check := config.CanonicalCheckName(f.Check)
		batch = append(batch, blockdigest.Handled{
			Check:       check,
			Severity:    f.Severity.String(),
			IP:          checks.ExtractIPFromFinding(f),
			BlockReason: summaryBlockReason(f),
			Muted:       muted[check],
		})
		if b, ok := d.wouldBlock(check, f); ok {
			collector.NoteWouldBlock(b)
		}
	}
	collector.NoteHandled(batch)
}
