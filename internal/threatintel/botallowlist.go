// Package threatintel -- bot allowlist + verification.
//
// botallowlist.go owns the embedded static IP CIDR ranges and the UA
// substring -> claimed-bot mapping. The static snapshots are a fast positive
// allow path: if the source IP falls inside a published bot range, skip the
// request without rDNS. Refreshed at runtime by the existing
// `csm update-rules` plumbing (separate task -- not in this commit).
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
		for bot, raw := range map[string][]byte{
			"googlebot": googlebotJSON,
			"bingbot":   bingbotJSON,
			"applebot":  applebotJSON,
		} {
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
	return false
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
	case strings.Contains(low, "gptbot"), strings.Contains(low, "chatgpt-user"):
		return "gptbot"
	case strings.Contains(low, "claudebot"), strings.Contains(low, "claude-searchbot"):
		return "claudebot"
	case strings.Contains(low, "perplexitybot"):
		return "perplexitybot"
	case strings.Contains(low, "meta-externalagent"), strings.Contains(low, "meta-webindexer"):
		return "facebookbot"
	case strings.Contains(low, "bravebot"):
		return "bravebot"
	default:
		return ""
	}
}
