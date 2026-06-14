package daemon

import (
	"context"
	"net/http"
	"path/filepath"
	"time"

	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/threatintel"
)

// botRangesUpdater periodically refreshes the published AI-crawler IP ranges
// (OpenAI, Perplexity) so GPTBot/ChatGPT-User/OAI-SearchBot/PerplexityBot stay
// verifiable by address without a new release. Embedded snapshots cover the gap
// before the first refresh and whenever a fetch fails.
func (d *Daemon) botRangesUpdater() {
	defer d.wg.Done()
	if !d.cfg.BotRangesAutoUpdate() {
		return
	}
	cachePath := filepath.Join(d.cfg.StatePath, "botranges.json")
	if err := threatintel.LoadFetchedRanges(cachePath); err != nil {
		csmlog.Warn("bot-ranges cache load failed", "err", err)
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
	if n > 0 {
		csmlog.Info("bot-ranges refreshed", "bots", n)
	}
}
