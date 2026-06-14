// Package threatintel -- bot allowlist + verification.
//
// botallowlist.go owns the embedded static IP CIDR ranges and the UA
// substring -> claimed-bot mapping. The static snapshots are a fast positive
// allow path: if the source IP falls inside a published bot range, skip the
// request without rDNS. The embedded snapshots are a trusted fallback; the
// bot-ranges auto-updater (botranges_update.go) refreshes them at runtime.
package threatintel

import (
	_ "embed"
	"encoding/json"
	"net"
	"strings"
	"sync"
)

//go:embed embed/googlebot.json
var googlebotJSON []byte

//go:embed embed/bingbot.json
var bingbotJSON []byte

//go:embed embed/applebot.json
var applebotJSON []byte

// AI crawlers publish IP ranges rather than crawler reverse DNS, so they ship
// as embedded snapshots and are kept current by the auto-updater. OpenAI's
// three feeds (GPTBot, ChatGPT-User, OAI-SearchBot) all verify "gptbot".
//
//go:embed embed/openai-gptbot.json
var openaiGPTBotJSON []byte

//go:embed embed/openai-chatgpt-user.json
var openaiChatGPTUserJSON []byte

//go:embed embed/openai-searchbot.json
var openaiSearchBotJSON []byte

//go:embed embed/perplexitybot.json
var perplexitybotJSON []byte

// BotRanges holds the parsed allowlist data, indexed by claimed-bot
// identity ("googlebot", "bingbot", "applebot").
type BotRanges struct {
	byBot map[string][]*net.IPNet
}

type embedFile struct {
	Prefixes []struct {
		IPv4 string `json:"ipv4Prefix"`
		IPv6 string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

var (
	defaultRanges *BotRanges
	rangesOnce    sync.Once
)

// DefaultRanges parses the embedded snapshots once and returns the
// global BotRanges. Safe to call concurrently.
func DefaultRanges() *BotRanges {
	rangesOnce.Do(func() {
		defaultRanges = &BotRanges{byBot: map[string][]*net.IPNet{}}
		// A slice (not a map) so several feeds can share one identity:
		// OpenAI's three crawler feeds all populate "gptbot".
		for _, src := range []struct {
			bot string
			raw []byte
		}{
			{"googlebot", googlebotJSON},
			{"bingbot", bingbotJSON},
			{"applebot", applebotJSON},
			{"gptbot", openaiGPTBotJSON},
			{"gptbot", openaiChatGPTUserJSON},
			{"gptbot", openaiSearchBotJSON},
			{"perplexitybot", perplexitybotJSON},
		} {
			bot, raw := src.bot, src.raw
			var f embedFile
			if err := json.Unmarshal(raw, &f); err != nil {
				continue
			}
			for _, p := range f.Prefixes {
				if cidr := p.IPv4; cidr != "" {
					if _, n, err := net.ParseCIDR(cidr); err == nil {
						defaultRanges.byBot[bot] = append(defaultRanges.byBot[bot], n)
					}
				}
				if cidr := p.IPv6; cidr != "" {
					if _, n, err := net.ParseCIDR(cidr); err == nil {
						defaultRanges.byBot[bot] = append(defaultRanges.byBot[bot], n)
					}
				}
			}
		}
	})
	return defaultRanges
}

// IPInBot reports whether the given IP falls inside the static range
// of the given bot identity.
func (r *BotRanges) IPInBot(ip net.IP, bot string) bool {
	if ip == nil {
		return false
	}
	for _, n := range r.byBot[bot] {
		if n.Contains(ip) {
			return true
		}
	}
	for _, n := range fetchedRangesFor(bot) {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IPInAnyBot reports whether the IP falls inside any published crawler
// range (Googlebot/Bingbot/Applebot snapshots). Unlike IPInBot it needs
// no claimed-UA, so callers that only have an IP (e.g. the incident
// correlator's whitelist backstop) can recognise a verified-crawler
// address. Deliberately covers only crawlers that publish authoritative
// IP ranges -- CDN edge ranges are NOT included, because legitimate and
// malicious traffic share a CDN's egress IPs and whitelisting them would
// hide attacks proxied through the CDN.
func (r *BotRanges) IPInAnyBot(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, nets := range r.byBot {
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
	}
	for _, nets := range fetchedRangesSnapshot() {
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// AICrawlerRangePrefixCounts returns the active prefix count for each built-in
// AI crawler that has a vendor range feed. Embedded snapshots are counted along
// with any fetched overlay so status views never report "none" while the
// packaged fallback ranges are still active.
func AICrawlerRangePrefixCounts() map[string]int {
	sourceBots := map[string]struct{}{}
	for _, src := range DefaultRangeSources() {
		sourceBots[src.Bot] = struct{}{}
	}

	seen := map[string]map[string]struct{}{}
	add := func(bot string, nets []*net.IPNet) {
		if len(nets) == 0 {
			return
		}
		if seen[bot] == nil {
			seen[bot] = map[string]struct{}{}
		}
		for _, n := range nets {
			if n != nil {
				seen[bot][n.String()] = struct{}{}
			}
		}
	}

	defaults := DefaultRanges()
	for bot := range sourceBots {
		add(bot, defaults.byBot[bot])
	}
	for bot, nets := range fetchedRangesSnapshot() {
		add(bot, nets)
	}

	out := make(map[string]int, len(seen))
	for bot, prefixes := range seen {
		out[bot] = len(prefixes)
	}
	return out
}

// ClaimedBotFromUA returns the lower-case bot identity if the UA looks
// like a known bot. Empty string otherwise. Identities match BotDomains
// keys in botverify.go so the async verifier can look up the right
// DNS suffix list.
func ClaimedBotFromUA(ua string) string {
	low := strings.ToLower(ua)
	switch {
	case strings.Contains(low, "googlebot"):
		return "googlebot"
	case strings.Contains(low, "bingbot"):
		return "bingbot"
	case strings.Contains(low, "applebot"):
		return "applebot"
	// Appendix A bots: no published static IP range.
	case strings.Contains(low, "duckduckbot"):
		return "duckduckbot"
	case strings.Contains(low, "amazonbot"):
		return "amazonbot"
	case strings.Contains(low, "gptbot"),
		strings.Contains(low, "chatgpt-user"),
		strings.Contains(low, "oai-searchbot"):
		return "gptbot"
	case strings.Contains(low, "claudebot"), strings.Contains(low, "claude-searchbot"):
		return "claudebot"
	case strings.Contains(low, "perplexitybot"):
		return "perplexitybot"
	case strings.Contains(low, "meta-externalagent"),
		strings.Contains(low, "meta-webindexer"),
		strings.Contains(low, "facebookexternalhit"):
		return "facebookbot"
	case strings.Contains(low, "bravebot"):
		return "bravebot"
	// SEO backlink crawlers: no published static IP range, rDNS-verified.
	case strings.Contains(low, "seranking"):
		return "seranking"
	default:
		// Operator-configured bots (reputation.verified_bots) extend the
		// built-in set without a code change.
		return OperatorBotFromUA(low)
	}
}
