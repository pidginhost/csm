package threatintel

import (
	"net"
	"testing"
)

// IPInAnyVerifiedBotRange is the IP-only lookup the firewall auto-block guard
// uses: it must recognise a published-crawler address (built-in/auto-updated
// snapshot) or an operator-configured IP-range bot without needing the UA.
func TestIPInAnyVerifiedBotRange(t *testing.T) {
	t.Cleanup(func() { SetOperatorBots(nil) })

	// Built-in snapshot: a published GPTBot address.
	if !IPInAnyVerifiedBotRange(net.ParseIP("74.7.241.37")) {
		t.Error("a published GPTBot IP should be a verified-bot range")
	}

	// Operator-configured IP-range bot (published PerplexityBot CIDR).
	SetOperatorBots([]BotEntry{{
		Name:         "perplexitybot",
		UASubstrings: []string{"perplexitybot"},
		IPRanges:     []string{"18.97.9.96/29"},
	}})
	if !IPInAnyVerifiedBotRange(net.ParseIP("18.97.9.100")) {
		t.Error("an operator-configured verified-bot IP should match")
	}
	if IPInAnyVerifiedBotRange(net.ParseIP("18.97.9.200")) {
		t.Error("an IP outside every verified-bot range must not match")
	}

	// Unrelated address and nil are never verified-bot ranges.
	if IPInAnyVerifiedBotRange(net.ParseIP("203.0.113.7")) {
		t.Error("an unrelated IP must not be a verified-bot range")
	}
	if IPInAnyVerifiedBotRange(nil) {
		t.Error("nil IP must not be a verified-bot range")
	}
}
