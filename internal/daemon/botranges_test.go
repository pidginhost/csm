package daemon

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/threatintel"
)

// reloadBotRanges is what the botranges.reload control command (issued by
// `csm update-bot-ranges`) calls: it republishes the freshly-written on-disk
// overlay into the running daemon and records the updater metric.
func TestReloadBotRanges_LoadsCacheAndRecordsMetrics(t *testing.T) {
	t.Cleanup(func() { threatintel.PublishFetchedRanges(nil) })

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "botranges.json")
	_, n, err := net.ParseCIDR("18.97.9.96/29") // published PerplexityBot range, passes the guard
	if err != nil {
		t.Fatal(err)
	}
	if err := threatintel.SaveFetchedRanges(cachePath, map[string][]*net.IPNet{"perplexitybot": {n}}); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	threatintel.PublishFetchedRanges(nil) // daemon starts with no overlay

	d := &Daemon{cfg: &config.Config{StatePath: dir}}
	if err := d.reloadBotRanges(); err != nil {
		t.Fatalf("reloadBotRanges: %v", err)
	}

	snap := threatintel.FetchedRangesSnapshot()
	if len(snap["perplexitybot"]) != 1 {
		t.Fatalf("reload did not publish cached ranges: %+v", snap)
	}

	_, prefixes, _ := botRangesMetrics()
	if got := prefixes.With("perplexitybot").Value(); got != 1 {
		t.Errorf("perplexitybot prefix gauge = %v, want 1", got)
	}
}

func TestReloadBotRanges_MissingCacheFails(t *testing.T) {
	t.Cleanup(func() { threatintel.PublishFetchedRanges(nil) })

	d := &Daemon{cfg: &config.Config{StatePath: t.TempDir()}}
	total, _, _ := botRangesMetrics()
	before := total.With("failure").Value()
	if err := d.reloadBotRanges(); err == nil {
		t.Fatal("reloadBotRanges should fail when the refreshed cache is missing")
	}
	if got := total.With("failure").Value() - before; got != 1 {
		t.Fatalf("failure counter delta = %v, want 1", got)
	}
}

func TestSetBotRangesPrefixGaugesClearsMissingBots(t *testing.T) {
	t.Cleanup(func() { threatintel.PublishFetchedRanges(nil) })

	_, oldNet, err := net.ParseCIDR("18.97.9.96/29")
	if err != nil {
		t.Fatal(err)
	}
	_, newNet, err := net.ParseCIDR("74.7.241.0/25")
	if err != nil {
		t.Fatal(err)
	}

	threatintel.PublishFetchedRanges(map[string][]*net.IPNet{"stalebot": {oldNet}})
	setBotRangesPrefixGauges()
	_, prefixes, _ := botRangesMetrics()
	if got := prefixes.With("stalebot").Value(); got != 1 {
		t.Fatalf("stalebot prefix gauge before removal = %v, want 1", got)
	}

	threatintel.PublishFetchedRanges(map[string][]*net.IPNet{"freshbot": {newNet}})
	setBotRangesPrefixGauges()
	if got := prefixes.With("stalebot").Value(); got != 0 {
		t.Fatalf("stalebot prefix gauge after removal = %v, want 0", got)
	}
	if got := prefixes.With("freshbot").Value(); got != 1 {
		t.Fatalf("freshbot prefix gauge = %v, want 1", got)
	}
}
