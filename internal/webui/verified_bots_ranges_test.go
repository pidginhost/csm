package webui

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/threatintel"
)

// The Verified Bots page surfaces the built-in AI-crawler range state read-only:
// the auto-update posture from config plus the live per-bot prefix counts.
func TestVerifiedBots_GetIncludesBotRangesSummary(t *testing.T) {
	t.Cleanup(func() { threatintel.PublishFetchedRanges(nil) })
	s, _ := newSettingsTestServer(t, "tok",
		"hostname: t.example.com\nreputation:\n  verified_bots: []\n  bot_ranges:\n    auto_update: true\n    update_interval: \"12h\"\n")

	_, n, err := net.ParseCIDR("18.97.9.96/29")
	if err != nil {
		t.Fatal(err)
	}
	threatintel.PublishFetchedRanges(map[string][]*net.IPNet{"perplexitybot": {n}})

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
	if resp.BotRanges.Prefixes["perplexitybot"] != 1 {
		t.Errorf("bot_ranges.prefixes[perplexitybot] = %d, want 1", resp.BotRanges.Prefixes["perplexitybot"])
	}
}
