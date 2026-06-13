package config

import (
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// VerifiedBot is one operator-configured good bot. A request whose UA
// contains any UASubstrings is treated as claiming this identity, and is
// trusted only if forward-confirmed reverse DNS places the source IP under
// one of RDNSSuffixes. Built-in bots are unaffected; this only adds coverage.
type VerifiedBot struct {
	Name         string   `yaml:"name"`
	UASubstrings []string `yaml:"ua_substrings"`
	RDNSSuffixes []string `yaml:"rdns_suffixes"`
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
		if !hasSuffix {
			results = append(results, ValidationResult{"error", field + ".rdns_suffixes",
				"at least one rdns_suffix is required"})
		}
	}
	return results
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
