package daemon

import (
	"context"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/threatintel"
)

var (
	botRangesRefreshTotal *metrics.CounterVec
	botRangesPrefixes     *metrics.GaugeVec
	botRangesLastSuccess  *metrics.Gauge
	botRangesMetricsOnce  sync.Once
	botRangesPrefixMu     sync.Mutex
	botRangesPrefixBots   = map[string]struct{}{}
)

// botRangesMetrics lazily registers and returns the AI-crawler range-updater
// metrics, mirroring the signature/geoip update metrics: a refresh
// success/failure counter, a per-bot prefix-count gauge, and the timestamp of
// the last successful refresh.
func botRangesMetrics() (*metrics.CounterVec, *metrics.GaugeVec, *metrics.Gauge) {
	botRangesMetricsOnce.Do(func() {
		botRangesRefreshTotal = metrics.NewCounterVec(
			"csm_botranges_refresh_total",
			"AI-crawler IP-range refresh attempts, labelled by result (success when at least one vendor feed updated).",
			[]string{"result"},
		)
		metrics.MustRegister("csm_botranges_refresh_total", botRangesRefreshTotal)
		botRangesPrefixes = metrics.NewGaugeVec(
			"csm_botranges_prefixes",
			"Current number of published IP prefixes per AI-crawler identity in the active overlay.",
			[]string{"bot"},
		)
		metrics.MustRegister("csm_botranges_prefixes", botRangesPrefixes)
		botRangesLastSuccess = metrics.NewGauge(
			"csm_botranges_last_success_timestamp_seconds",
			"Unix timestamp of the last successful AI-crawler IP-range refresh.",
		)
		metrics.MustRegister("csm_botranges_last_success_timestamp_seconds", botRangesLastSuccess)
	})
	return botRangesRefreshTotal, botRangesPrefixes, botRangesLastSuccess
}

// setBotRangesPrefixGauges syncs the per-bot prefix gauge to the active overlay.
func setBotRangesPrefixGauges() {
	_, prefixes, _ := botRangesMetrics()
	snap := threatintel.FetchedRangesSnapshot()
	botRangesPrefixMu.Lock()
	defer botRangesPrefixMu.Unlock()
	for bot := range botRangesPrefixBots {
		if _, ok := snap[bot]; !ok {
			prefixes.With(bot).Set(0)
			delete(botRangesPrefixBots, bot)
		}
	}
	for bot, nets := range snap {
		prefixes.With(bot).Set(float64(len(nets)))
		botRangesPrefixBots[bot] = struct{}{}
	}
}

// observeBotRangesRefresh records the outcome of a refresh attempt. On success
// it bumps the prefix gauges and last-success timestamp; on failure it only
// increments the failure counter so the previous overlay's gauges stand.
func observeBotRangesRefresh(success bool) {
	total, _, lastSuccess := botRangesMetrics()
	if !success {
		total.With("failure").Inc()
		return
	}
	total.With("success").Inc()
	setBotRangesPrefixGauges()
	lastSuccess.Set(float64(time.Now().Unix()))
}

func (d *Daemon) botRangesCachePath() string {
	return filepath.Join(d.cfg.StatePath, "botranges.json")
}

// reloadBotRanges republishes the on-disk overlay into the running daemon. It
// is the botranges.reload control handler's worker: `csm update-bot-ranges`
// fetches fresh ranges, writes the cache, then asks the daemon to reload so the
// new ranges take effect without a restart.
func (d *Daemon) reloadBotRanges() error {
	if err := threatintel.LoadFetchedRangesRequired(d.botRangesCachePath()); err != nil {
		observeBotRangesRefresh(false)
		return err
	}
	observeBotRangesRefresh(true)
	return nil
}

// botRangesUpdater periodically refreshes the published AI-crawler IP ranges
// (OpenAI, Perplexity) so GPTBot/ChatGPT-User/OAI-SearchBot/PerplexityBot stay
// verifiable by address without a new release. Embedded snapshots cover the gap
// before the first refresh and whenever a fetch fails.
func (d *Daemon) botRangesUpdater() {
	defer d.wg.Done()
	if !d.cfg.BotRangesAutoUpdate() {
		return
	}
	cachePath := d.botRangesCachePath()
	if err := threatintel.LoadFetchedRanges(cachePath); err != nil {
		csmlog.Warn("bot-ranges cache load failed", "err", err)
	} else {
		// Reflect the cached overlay in the gauge before the first refresh.
		setBotRangesPrefixGauges()
	}

	interval := 24 * time.Hour
	if s := d.cfg.Reputation.BotRanges.UpdateInterval; s != "" {
		if v, err := time.ParseDuration(s); err == nil && v >= time.Hour {
			interval = v
		}
	}

	select {
	case <-d.stopCh:
		return
	case <-time.After(5 * time.Minute):
	}
	d.doBotRangesUpdate(cachePath)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.doBotRangesUpdate(cachePath)
		}
	}
}

func (d *Daemon) doBotRangesUpdate(cachePath string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Cancel an in-flight fetch promptly on daemon shutdown.
	go func() {
		select {
		case <-d.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	client := &http.Client{Timeout: 30 * time.Second}
	n, err := threatintel.RefreshFetchedRanges(ctx, client, threatintel.DefaultRangeSources(), cachePath)
	if err != nil {
		csmlog.Warn("bot-ranges refresh error", "err", err)
	}
	observeBotRangesRefresh(n > 0)
	if n > 0 {
		csmlog.Info("bot-ranges refreshed", "bots", n)
	}
}
