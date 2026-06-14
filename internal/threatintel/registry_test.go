package threatintel

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestOperatorBotFromUA(t *testing.T) {
	t.Cleanup(func() { SetOperatorBots(nil) })
	SetOperatorBots([]BotEntry{{
		Name:         "SERanking",                       // mixed case -> lowercased
		UASubstrings: []string{"SERankingBacklinksBot"}, // matched case-insensitively
		RDNSSuffixes: []string{".SeRanking.com"},        // leading dot + case normalized
	}})

	if got := OperatorBotFromUA("mozilla/5.0 (compatible; serankingbacklinksbot/1.0)"); got != "seranking" {
		t.Errorf("OperatorBotFromUA(crawler) = %q, want seranking", got)
	}
	if got := OperatorBotFromUA("Mozilla/5.0 (compatible; SERankingBacklinksBot/1.0)"); got != "seranking" {
		t.Errorf("OperatorBotFromUA(raw crawler) = %q, want seranking", got)
	}
	if got := OperatorBotFromUA("mozilla/5.0 (windows nt 10.0; chrome/120)"); got != "" {
		t.Errorf("OperatorBotFromUA(browser) = %q, want empty", got)
	}
	if got := operatorDomains("seranking"); len(got) != 1 || got[0] != "seranking.com" {
		t.Errorf("operatorDomains = %v, want [seranking.com]", got)
	}
}

func TestClaimedBotFromUA_OperatorEntry(t *testing.T) {
	t.Cleanup(func() { SetOperatorBots(nil) })
	SetOperatorBots([]BotEntry{{
		Name:         "acmebot",
		UASubstrings: []string{"acmecrawler"},
		RDNSSuffixes: []string{"acme.example"},
	}})

	if got := ClaimedBotFromUA("Mozilla/5.0 (compatible; AcmeCrawler/2.0)"); got != "acmebot" {
		t.Errorf("ClaimedBotFromUA(operator) = %q, want acmebot", got)
	}
	// Built-in identities still resolve and take precedence over operator entries.
	if got := ClaimedBotFromUA("Googlebot/2.1"); got != "googlebot" {
		t.Errorf("ClaimedBotFromUA(googlebot) = %q, want googlebot", got)
	}
}

func TestOperatorBotsCacheVersion(t *testing.T) {
	base := 3
	a := []BotEntry{{Name: "x", UASubstrings: []string{"xbot"}, RDNSSuffixes: []string{"x.example"}}}
	b := []BotEntry{{Name: "x", UASubstrings: []string{"xbot"}, RDNSSuffixes: []string{"y.example"}}}

	reordered := []BotEntry{{Name: " X ", UASubstrings: []string{" XBot "}, RDNSSuffixes: []string{" .X.Example "}}}
	if OperatorBotsCacheVersion(base, a) != OperatorBotsCacheVersion(base, reordered) {
		t.Error("cache version must be stable for equivalent normalized entries")
	}
	if OperatorBotsCacheVersion(base, a) == OperatorBotsCacheVersion(base, b) {
		t.Error("cache version must change when a suffix changes")
	}
	if OperatorBotsCacheVersion(base, a) == OperatorBotsCacheVersion(base+1, a) {
		t.Error("cache version must change when the base logic version changes")
	}
	if OperatorBotsCacheVersion(base, nil) == OperatorBotsCacheVersion(base, a) {
		t.Error("cache version with entries must differ from the empty list")
	}
}

// An operator-configured bot verifies through the same FCrDNS path as a
// built-in once SetOperatorEntries installs its suffix list.
func TestAsyncBotVerifier_OperatorEntryVerifies(t *testing.T) {
	ip := "203.0.113.9"
	var gotVerified, gotValid bool
	a := NewAsyncBotVerifier(func(_ net.IP, bot string, verified bool, _ time.Time) error {
		if bot == "acmebot" {
			gotVerified, gotValid = verified, true
		}
		return nil
	})
	a.res = &mockResolver{
		ptr: map[string][]string{ip: {"crawl-9.acme.example."}},
		a:   map[string][]net.IP{"crawl-9.acme.example": {net.ParseIP(ip)}},
	}
	a.SetOperatorEntries([]BotEntry{{Name: " AcmeBot ", UASubstrings: []string{"AcmeCrawler"}, RDNSSuffixes: []string{" .Acme.Example "}}})

	a.process(verifyJob{IP: net.ParseIP(ip), Bot: "acmebot"})

	if !gotValid || !gotVerified {
		t.Fatalf("operator bot FCrDNS: valid=%v verified=%v, want true,true", gotValid, gotVerified)
	}
}

// An operator entry naming a built-in extends that bot's suffix list rather
// than replacing it, so both the built-in and the added suffix verify.
func TestAsyncBotVerifier_OperatorExtendsBuiltinSuffixes(t *testing.T) {
	a := NewAsyncBotVerifier(func(net.IP, string, bool, time.Time) error { return nil })
	a.res = &mockResolver{
		ptr: map[string][]string{
			"203.0.113.20": {"node.extra.example."},
			"66.249.66.99": {"crawl-66-249-66-99.googlebot.com."},
		},
		a: map[string][]net.IP{
			"node.extra.example":               {net.ParseIP("203.0.113.20")},
			"crawl-66-249-66-99.googlebot.com": {net.ParseIP("66.249.66.99")},
		},
	}
	a.SetOperatorEntries([]BotEntry{{Name: "googlebot", RDNSSuffixes: []string{"extra.example"}}})

	if ok, err := a.v["googlebot"].verify(context.Background(), net.ParseIP("203.0.113.20"), "googlebot"); err != nil || !ok {
		t.Fatalf("operator-added googlebot suffix must verify: ok=%v err=%v", ok, err)
	}
	if ok, err := a.v["googlebot"].verify(context.Background(), net.ParseIP("66.249.66.99"), "googlebot"); err != nil || !ok {
		t.Fatalf("built-in googlebot suffix must still verify after extension: ok=%v err=%v", ok, err)
	}
}

// Operator IP-range bots (AI agents that publish ranges, not rDNS) verify
// synchronously by CIDR membership -- no PTR, no async cache.
func TestOperatorBotIPVerified(t *testing.T) {
	t.Cleanup(func() { SetOperatorBots(nil) })
	SetOperatorBots([]BotEntry{{
		Name:         "perplexitybot",
		UASubstrings: []string{"perplexitybot"},
		IPRanges:     []string{"18.97.9.96/29", "203.0.113.7"},
	}})

	if !OperatorBotIPVerified("perplexitybot", net.ParseIP("18.97.9.100")) {
		t.Error("IP inside /29 must verify")
	}
	if !OperatorBotIPVerified("perplexitybot", net.ParseIP("203.0.113.7")) {
		t.Error("single configured IP must verify")
	}
	if OperatorBotIPVerified("perplexitybot", net.ParseIP("18.97.9.200")) {
		t.Error("IP outside the configured ranges must not verify")
	}
	if OperatorBotIPVerified("other", net.ParseIP("18.97.9.100")) {
		t.Error("a different bot name must not verify")
	}
}
