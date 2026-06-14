package config

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// VerifiedBot is one operator-configured good bot. A request whose UA contains
// any UASubstrings is treated as claiming this identity, and is trusted only
// if the source IP matches one configured verification method.
type VerifiedBot struct {
	Name         string   `yaml:"name" json:"name"`
	UASubstrings []string `yaml:"ua_substrings,omitempty" json:"ua_substrings,omitempty"`
	RDNSSuffixes []string `yaml:"rdns_suffixes,omitempty" json:"rdns_suffixes,omitempty"`
	// IPRanges are published CIDRs (or single IPs) for bots that verify by
	// address rather than reverse DNS -- typically AI agents (PerplexityBot,
	// GPTBot, ClaudeBot). Membership is checked synchronously; no rDNS lookup.
	IPRanges []string `yaml:"ip_ranges,omitempty" json:"ip_ranges,omitempty"`
}

// verifiedBotMinUALen rejects UA substrings short enough to match unrelated
// traffic ("bot", "go"). Real crawler tokens are longer.
const verifiedBotMinUALen = 4

// browserUATokens are substrings that appear in ordinary browser UAs. Entries
// keyed only on these tokens would match real users, so validation rejects
// them unless the substring also carries a crawler-specific token.
var browserUATokens = map[string]bool{
	"mozilla": true, "applewebkit": true, "webkit": true, "gecko": true,
	"chrome": true, "safari": true, "firefox": true, "edge": true,
	"opera": true, "msie": true, "trident": true, "windows": true,
	"macintosh": true, "linux": true, "android": true, "iphone": true,
	"ipad": true, "x11": true, "mobile": true,
}

var crawlerUATokens = []string{
	"bot", "crawler", "spider", "externalhit", "inspectiontool", "lighthouse",
}

// sharedHostingSuffixes are domains where reverse DNS is assigned to whoever
// rents the address, so an attacker can obtain a PTR (and forward A) under
// them. Allowlisting such a suffix would let any tenant spoof a crawler, so
// they are rejected. Matched as a suffix so subdomains are caught too.
var sharedHostingSuffixes = []string{
	"amazonaws.com", "googleusercontent.com", "appspot.com", "run.app",
	"cloudfront.net", "azurewebsites.net", "cloudapp.azure.com",
	"herokuapp.com", "workers.dev", "pages.dev", "netlify.app",
	"vercel.app", "ondigitalocean.app", "digitaloceanspaces.com",
	"github.io", "gitlab.io", "fastly.net", "akamaitechnologies.com",
	"akamai.net", "cloudflare.net", "colocrossing.com", "contabo.net",
	"hetzner.com", "your-server.de", "ovh.net", "ip-linodeusercontent.com",
	"linode.com", "vultrusercontent.com",
}

// commonPublicSuffixes are multi-label public suffixes that are not
// registrable on their own; a crawler can never legitimately be the whole
// suffix. Bare single-label TLDs are caught by the label-count check.
var commonPublicSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "co.jp": true,
	"com.br": true, "com.cn": true, "co.in": true, "co.za": true,
	"com.tr": true, "com.mx": true, "co.kr": true, "com.sg": true,
}

func validateVerifiedBots(cfg *Config) []ValidationResult {
	var results []ValidationResult
	seen := map[string]bool{}
	seenUA := map[string]string{}
	for i, b := range cfg.Reputation.VerifiedBots {
		field := fmt.Sprintf("reputation.verified_bots[%d]", i)
		name := strings.ToLower(strings.TrimSpace(b.Name))
		if name == "" {
			results = append(results, ValidationResult{"error", field + ".name", "verified bot name is required"})
			continue
		}
		if seen[name] {
			results = append(results, ValidationResult{"error", field + ".name",
				fmt.Sprintf("duplicate verified bot name %q", name)})
		}
		seen[name] = true

		hasUA := false
		for _, raw := range b.UASubstrings {
			s := strings.ToLower(strings.TrimSpace(raw))
			if s == "" {
				continue
			}
			hasUA = true
			if len(s) < verifiedBotMinUALen {
				results = append(results, ValidationResult{"error", field + ".ua_substrings",
					fmt.Sprintf("UA substring %q is too short (min %d chars)", s, verifiedBotMinUALen)})
			}
			if browserUASubstringFootgun(s) {
				results = append(results, ValidationResult{"error", field + ".ua_substrings",
					fmt.Sprintf("UA substring %q matches ordinary browsers and would allowlist real users", s)})
			}
			if prev, ok := seenUA[s]; ok && prev != name {
				results = append(results, ValidationResult{"error", field + ".ua_substrings",
					fmt.Sprintf("UA substring %q is already used by verified bot %q", s, prev)})
			}
			for prev, prevName := range seenUA {
				if prevName == name || prev == s {
					continue
				}
				if strings.Contains(prev, s) || strings.Contains(s, prev) {
					results = append(results, ValidationResult{"error", field + ".ua_substrings",
						fmt.Sprintf("UA substring %q overlaps verified bot %q substring %q", s, prevName, prev)})
					break
				}
			}
			if _, ok := seenUA[s]; !ok {
				seenUA[s] = name
			}
		}
		if !hasUA {
			results = append(results, ValidationResult{"error", field + ".ua_substrings",
				"at least one ua_substring is required"})
		}

		hasSuffix := false
		for _, raw := range b.RDNSSuffixes {
			s := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), ".")
			if s == "" {
				continue
			}
			hasSuffix = true
			if msg := verifiedBotSuffixError(s); msg != "" {
				results = append(results, ValidationResult{"error", field + ".rdns_suffixes", msg})
			}
		}

		hasRange := false
		for _, raw := range b.IPRanges {
			s := strings.TrimSpace(raw)
			if s == "" {
				continue
			}
			hasRange = true
			if msg := verifiedBotIPRangeError(s); msg != "" {
				results = append(results, ValidationResult{"error", field + ".ip_ranges", msg})
			}
		}

		// A bot needs at least one way to be confirmed: an rDNS suffix (for
		// crawlers with forward-confirmable reverse DNS) or an IP range (for
		// AI agents that publish address ranges instead of rDNS).
		if !hasSuffix && !hasRange {
			results = append(results, ValidationResult{"error", field,
				"at least one rdns_suffix or ip_range is required"})
		}
	}
	return results
}

// verifiedBotIPRangeError validates an operator-supplied CIDR or single IP.
// It rejects ranges too broad to be a crawler fleet and non-public space, so
// the allowlist cannot be turned into a blanket detection bypass.
func verifiedBotIPRangeError(s string) string {
	n := parseCIDROrIP(s)
	if n == nil {
		return fmt.Sprintf("ip_range %q is not a valid CIDR or IP", s)
	}
	ones, bits := n.Mask.Size()
	if bits == 32 && ones < 16 {
		return fmt.Sprintf("ip_range %q is too broad (minimum prefix /16 for IPv4)", s)
	}
	if bits == 128 && ones < 32 {
		return fmt.Sprintf("ip_range %q is too broad (minimum prefix /32 for IPv6)", s)
	}
	ip := n.IP
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ipInAnyNet(ip, nonPublicSpecialUseNets) {
		return fmt.Sprintf("ip_range %q is not a public address range", s)
	}
	return ""
}

var nonPublicSpecialUseNets = mustParseCIDRs(
	"100.64.0.0/10",   // carrier-grade NAT
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation
	"203.0.113.0/24",  // documentation
	"240.0.0.0/4",     // reserved
	"100::/64",        // discard-only
	"2001:2::/48",     // benchmarking
	"2001:db8::/32",   // documentation
	"2002::/16",       // 6to4
	"64:ff9b::/96",    // IPv4/IPv6 translation
	"64:ff9b:1::/48",  // IPv4/IPv6 translation
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

func ipInAnyNet(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIDROrIP(s string) *net.IPNet {
	s = strings.TrimSpace(s)
	if _, n, err := net.ParseCIDR(s); err == nil {
		return normalizeIPNet(n)
	}
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
	}
	return nil
}

func normalizeIPNet(n *net.IPNet) *net.IPNet {
	if n == nil {
		return nil
	}
	if v4 := n.IP.To4(); v4 != nil {
		mask := n.Mask
		if len(mask) == net.IPv6len {
			// Go treats IPv4-mapped IPv6 CIDRs as IPv4 ranges for Contains.
			// Validate the same effective IPv4 prefix instead of the /96
			// mapped wrapper.
			mask = net.IPMask(mask[12:])
		}
		if len(mask) != net.IPv4len {
			return nil
		}
		return &net.IPNet{IP: v4.Mask(mask), Mask: mask}
	}
	ip := n.IP.To16()
	if ip == nil || len(n.Mask) != net.IPv6len {
		return nil
	}
	return &net.IPNet{IP: ip.Mask(n.Mask), Mask: n.Mask}
}

func browserUASubstringFootgun(s string) bool {
	if !containsKnownUAToken(s, browserUATokens) {
		return false
	}
	for _, token := range crawlerUATokens {
		if strings.Contains(s, token) {
			return false
		}
	}
	return true
}

func containsKnownUAToken(s string, tokens map[string]bool) bool {
	for token := range tokens {
		for start := 0; start < len(s); {
			idx := strings.Index(s[start:], token)
			if idx == -1 {
				break
			}
			idx += start
			end := idx + len(token)
			if uaTokenBoundary(s, idx-1) && uaTokenBoundary(s, end) {
				return true
			}
			start = idx + 1
		}
	}
	return false
}

func uaTokenBoundary(s string, idx int) bool {
	if idx < 0 || idx >= len(s) {
		return true
	}
	c := s[idx]
	if c >= 'a' && c <= 'z' {
		return false
	}
	if c >= '0' && c <= '9' {
		return false
	}
	return true
}

func validateVerifiedBotsConfig(cfg *Config) error {
	for _, r := range validateVerifiedBots(cfg) {
		if r.Level == "error" {
			return fmt.Errorf("%s: %s", r.Field, r.Message)
		}
	}
	return nil
}

func verifiedBotSuffixError(s string) string {
	if strings.ContainsAny(s, " /:") {
		return fmt.Sprintf("rdns_suffix %q is not a domain", s)
	}
	if len(s) > 253 {
		return fmt.Sprintf("rdns_suffix %q is too long", s)
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return fmt.Sprintf("rdns_suffix %q must be a registrable domain (e.g. seranking.com), not a bare TLD", s)
	}
	for _, l := range labels {
		if l == "" {
			return fmt.Sprintf("rdns_suffix %q has an empty label", s)
		}
		if len(l) > 63 {
			return fmt.Sprintf("rdns_suffix %q has a label longer than 63 characters", s)
		}
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return fmt.Sprintf("rdns_suffix %q has a label starting or ending with hyphen", s)
		}
		for _, r := range l {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return fmt.Sprintf("rdns_suffix %q has invalid domain characters", s)
		}
	}
	if commonPublicSuffixes[s] {
		return fmt.Sprintf("rdns_suffix %q is a public suffix, not a registrable domain", s)
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(s); err != nil {
		return fmt.Sprintf("rdns_suffix %q is a public suffix, not a registrable domain", s)
	}
	for _, bad := range sharedHostingSuffixes {
		if s == bad || strings.HasSuffix(s, "."+bad) {
			return fmt.Sprintf("rdns_suffix %q is shared hosting where reverse DNS is attacker-controlled; not allowed", s)
		}
	}
	return ""
}
