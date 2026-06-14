package threatintel

import (
	"net"
	"testing"
)

// Anthropic now publishes a machine-readable crawler IP feed
// (claude.com/crawling/bots.json), so ClaudeBot is verifiable by address from
// the embedded snapshot, not only by reverse DNS.
func TestDefaultRanges_ClaudeBotBuiltIn(t *testing.T) {
	r := DefaultRanges()
	if !r.IPInBot(net.ParseIP("216.73.216.5"), "claudebot") {
		t.Error("an IP inside the published ClaudeBot /22 should be in the claudebot range")
	}
	if !r.IPInBot(net.ParseIP("34.162.230.222"), "claudebot") {
		t.Error("a published ClaudeBot /32 should be in the claudebot range")
	}
	if r.IPInBot(net.ParseIP("203.0.113.7"), "claudebot") {
		t.Error("an unrelated IP must not be in the claudebot range")
	}
}

func TestClaimedBotFromUA_ClaudeVariants(t *testing.T) {
	for _, ua := range []string{
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claude.com/bot)",
		"Claude-User/1.0",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +claude.com/bot)",
	} {
		if got := ClaimedBotFromUA(ua); got != "claudebot" {
			t.Errorf("ClaimedBotFromUA(%q) = %q, want claudebot", ua, got)
		}
	}
}

func TestDefaultRangeSources_IncludesClaudeBot(t *testing.T) {
	found := false
	for _, src := range DefaultRangeSources() {
		if src.Bot == "claudebot" {
			found = true
			if src.URL == "" {
				t.Error("claudebot range source has an empty URL")
			}
		}
	}
	if !found {
		t.Error("DefaultRangeSources must include a claudebot feed so the auto-updater refreshes it")
	}
}
