package threatintel

import (
	"net"
	"testing"
)

// The embedded AI-vendor snapshots make GPTBot and PerplexityBot verifiable by
// IP range, with no rDNS and no operator config.
func TestDefaultRanges_AIBotsBuiltIn(t *testing.T) {
	r := DefaultRanges()
	if !r.IPInBot(net.ParseIP("74.7.241.37"), "gptbot") {
		t.Error("a published GPTBot IP should be inside the gptbot range")
	}
	if !r.IPInBot(net.ParseIP("18.97.9.100"), "perplexitybot") {
		t.Error("a published PerplexityBot IP should be inside the perplexitybot range")
	}
	if r.IPInBot(net.ParseIP("203.0.113.7"), "gptbot") {
		t.Error("an unrelated IP must not be inside the gptbot range")
	}
}

func TestClaimedBotFromUA_OAISearchBot(t *testing.T) {
	ua := "Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)"
	if got := ClaimedBotFromUA(ua); got != "gptbot" {
		t.Errorf("ClaimedBotFromUA(OAI-SearchBot) = %q, want gptbot", got)
	}
}
