package webui

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/threatintel"
)

// The Verified Bots page surfaces the built-in AI-crawler range state read-only:
// the auto-update posture from config plus the live per-bot prefix counts.
func TestVerifiedBots_GetIncludesBotRangesSummary(t *testing.T) {
	t.Cleanup(func() { threatintel.PublishFetchedRanges(nil) })
	s, _ := newSettingsTestServer(t, "tok",
		"hostname: t.example.com\nreputation:\n  verified_bots: []\n  bot_ranges:\n    auto_update: true\n    update_interval: \"12h\"\n")

	_, n, err := net.ParseCIDR("9.9.9.0/24")
	if err != nil {
		t.Fatal(err)
	}
	basePrefixes := threatintel.AICrawlerRangePrefixCounts()
	cachePath := filepath.Join(t.TempDir(), "botranges.json")
	if err := threatintel.SaveFetchedRanges(cachePath, map[string][]*net.IPNet{"perplexitybot": {n}}); err != nil {
		t.Fatalf("save cache: %v", err)
	}
	if err := threatintel.LoadFetchedRanges(cachePath); err != nil {
		t.Fatalf("load cache: %v", err)
	}

	req := settingsAuthedReq("GET", "/api/v1/verified-bots", "tok", "")
	w := httptest.NewRecorder()
	s.apiVerifiedBots(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET code=%d body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		BotRanges struct {
			AutoUpdate     bool           `json:"auto_update"`
			UpdateInterval string         `json:"update_interval"`
			LastRefresh    string         `json:"last_refresh"`
			Prefixes       map[string]int `json:"prefixes"`
		} `json:"bot_ranges"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.BotRanges.AutoUpdate {
		t.Error("bot_ranges.auto_update should be true")
	}
	if resp.BotRanges.UpdateInterval != "12h" {
		t.Errorf("bot_ranges.update_interval = %q, want 12h", resp.BotRanges.UpdateInterval)
	}
	if _, err := time.Parse(time.RFC3339, resp.BotRanges.LastRefresh); err != nil {
		t.Errorf("bot_ranges.last_refresh = %q, want RFC3339 timestamp: %v", resp.BotRanges.LastRefresh, err)
	}
	wantPerplexity := basePrefixes["perplexitybot"] + 1
	if resp.BotRanges.Prefixes["perplexitybot"] != wantPerplexity {
		t.Errorf("bot_ranges.prefixes[perplexitybot] = %d, want %d", resp.BotRanges.Prefixes["perplexitybot"], wantPerplexity)
	}
	if resp.BotRanges.Prefixes["gptbot"] == 0 {
		t.Error("bot_ranges.prefixes[gptbot] should include embedded fallback ranges")
	}
}
