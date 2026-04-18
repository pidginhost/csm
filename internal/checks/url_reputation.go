package checks

import (
	"net"
	"net/url"
	"strings"
)

// URL reputation — attack-indicator based classifier for external
// <script src="..."> URLs embedded in WordPress content.
//
// PHILOSOPHY
//
// Earlier versions of this package classified script sources against a
// hardcoded allowlist of "known safe" domains (Google Tag Manager,
// Cloudflare CDN, HubSpot, Stripe, etc.). In practice the allowlist is
// unmaintainable: every new widget service (OneTrust, Issuu, regional
// video embeds, tax-form widgets, etc.) adds an entry and operators
// still see HIGH-severity findings for legitimate third-party embeds.
//
// This file takes the inverse approach: rather than asking "is this
// domain on my list of safe services?", it asks "does this URL show
// attacker-characteristic markers?". A <script src> fires a finding
// only when at least one attack indicator is present:
//
//   - the host is a raw IP address (attackers dodge domain reputation);
//   - the host TLD is on a well-known abused-TLD list (.tk, .ml, .ga,
//     .cf, .gq free-abuse; .top, .icu, .click, .pw and similar cheap
//     gTLDs per Spamhaus recurring bad-TLD reports);
//   - the host is on the existing short known-bad-exfil list
//     (Cloudflare Workers free tier, Pastebin raw, GitHub Gist raw —
//     legitimate content rarely loads from these hosts);
//   - the scheme is plaintext HTTP (an external JS loader without TLS
//     is a plaintext MITM target regardless of the destination);
//   - the host is empty, contains no dot, or otherwise fails basic
//     FQDN validation.
//
// The knownSafeDomains list is retained as a FAST-PATH tie-breaker: if
// the host matches a well-known service we return "not malicious"
// immediately, skipping further analysis. It is an optimization, not
// the primary filter. Unknown hosts on unremarkable TLDs (e.g.
// onetrust.com, issuu.com, trilulilu.ro, formular230.ro) pass because
// they have zero attack indicators — no allowlist growth needed.
//
// TRADE-OFF
//
// An attacker who hosts payload on a compromised mainstream domain
// (.com/.org/.net HTTPS, normal-looking path) is not caught. This gap
// existed under the prior allowlist too — it is a fundamental limit of
// URL-only classification. Closing it requires threat-intelligence
// correlation or content-based JS analysis, both of which are out of
// scope here. The defensive value is in raising the bar for casual
// injection, not in defeating sophisticated adversaries.

// abusedTLDs are top-level domains whose registrations are cheap,
// unverified, and overwhelmingly abused for phishing, malware, and SEO
// spam per recurring Spamhaus and KnowBe4 reports.
//
// The entry bar is high: a TLD is included only if (a) it has shown up
// in top-10 abuse rankings across multiple reporting years, AND
// (b) legitimate business usage is rare. Mixed-use TLDs with
// significant legitimate traffic (.xyz, .online, .site, .live, .space)
// are intentionally excluded to keep false-positive rates low.
//
// Entries are stored without the leading dot; comparison strips the
// leading dot from the observed TLD before lookup.
var abusedTLDs = map[string]bool{
	// Former Freenom TLDs — free registration, no verification.
	// Near-100% abuse rate; Freenom itself was shut down in 2023 but
	// the TLDs remain in DNS.
	"tk": true,
	"ml": true,
	"ga": true,
	"cf": true,
	"gq": true,

	// Cheap new gTLDs consistently in the Spamhaus top-abused list.
	"top":      true,
	"icu":      true,
	"click":    true,
	"pw":       true,
	"loan":     true,
	"work":     true,
	"download": true,

	// Spamhaus badlist recurring entries — legitimate usage is
	// essentially nonexistent at meaningful volume.
	"kim":     true,
	"gdn":     true,
	"stream":  true,
	"bid":     true,
	"racing":  true,
	"win":     true,
	"party":   true,
	"science": true,
	"trade":   true,
}

// knownBadExfilHosts are hosts where legitimate WordPress content
// essentially never loads JavaScript from, but attackers routinely do.
// The list is intentionally short — see knownSafeDomains for the
// inverse fast-path.
var knownBadExfilHosts = []string{
	// Cloudflare Workers free-tier subdomain (e.g. x.workers.dev).
	// Legitimate apps host on custom domains; free .workers.dev is a
	// common payload drop.
	".workers.dev",
	// Pastebin and GitHub Gist raw endpoints — legitimate sites do not
	// load JS from these paths.
	"pastebin.com",
	"gist.githubusercontent.com",
	// bit.ly and similar URL shorteners in a <script src> are a very
	// strong attack signal — no legitimate embed uses a shortener for
	// a JS asset.
	"bit.ly",
	"tinyurl.com",
	"is.gd",
	"cutt.ly",
}

// scriptSrcStrongReason classifies a <script src> URL by structural
// attack indicators that are context-independent: a raw IP host, an
// abused TLD, a known-bad exfil host, or an empty/unparseable/no-TLD
// host. These markers are rare-to-nonexistent in legitimate content of
// any age and remain valid signals whether the script appears in a
// freshly-written wp_options value or in decade-old post_content.
//
// Callers that operate on storage which is expected to hold current
// configuration (wp_options) should prefer scriptSrcMaliciousReason,
// which layers the plaintext-HTTP indicator on top. The HTTP signal
// catches attacker convenience ("don't bother with TLS") in fresh
// configuration but produces false positives on legacy author content
// where pre-TLS embeds are normal.
//
// The function does not consult knownSafeDomains — callers should do
// that first as a fast path. Separating the two concerns keeps this
// function single-purpose and trivially testable.
func scriptSrcStrongReason(rawURL string) (bool, string) {
	normalised := rawURL
	if strings.HasPrefix(normalised, "//") {
		normalised = "https:" + normalised
	}

	u, err := url.Parse(normalised)
	if err != nil || u == nil {
		return true, "unparseable URL"
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return true, "empty host"
	}

	if ip := net.ParseIP(host); ip != nil {
		return true, "raw IP address host"
	}

	for _, bad := range knownBadExfilHosts {
		if host == strings.TrimPrefix(bad, ".") {
			return true, "known-bad exfil host: " + bad
		}
		if strings.HasSuffix(host, bad) {
			return true, "known-bad exfil host: " + bad
		}
	}

	lastDot := strings.LastIndexByte(host, '.')
	if lastDot < 0 || lastDot == len(host)-1 {
		return true, "host without valid TLD"
	}
	tld := host[lastDot+1:]
	if abusedTLDs[tld] {
		return true, "abused TLD: ." + tld
	}

	return false, ""
}

// scriptSrcMaliciousReason classifies a <script src> URL with the full
// indicator set: everything scriptSrcStrongReason flags, plus plaintext
// HTTP. This is the classifier for wp_options and similar configuration
// storage, where a plaintext HTTP external script loader is a signal on
// its own (a site's analytics configuration should be HTTPS in 2026).
//
// The function does not consult knownSafeDomains — callers should do
// that first as a fast path.
func scriptSrcMaliciousReason(rawURL string) (bool, string) {
	// Structural markers take precedence: a raw-IP host over HTTP should
	// report the IP, not the scheme, because the scheme is merely the
	// delivery method while the IP is the identity of the attacker
	// infrastructure.
	if bad, reason := scriptSrcStrongReason(rawURL); bad {
		return true, reason
	}

	// Plaintext HTTP for an external script is a strong indicator in
	// configuration storage. Protocol-relative URLs (//host/path)
	// inherit the page's scheme and are not flagged here.
	normalised := rawURL
	if strings.HasPrefix(normalised, "//") {
		normalised = "https:" + normalised
	}
	u, err := url.Parse(normalised)
	if err != nil || u == nil {
		// scriptSrcStrongReason would have caught this; defensive only.
		return true, "unparseable URL"
	}
	if strings.EqualFold(u.Scheme, "http") && !strings.HasPrefix(rawURL, "//") {
		return true, "plaintext HTTP external script"
	}

	return false, ""
}

// isAttackerScriptURL is the caller-facing predicate for contexts where
// a plaintext-HTTP external script is a signal on its own (wp_options
// and similar configuration storage). It combines the known-safe fast
// path with the strict attack-indicator classifier.
//
// The order matters: the fast path is checked first because it lets us
// short-circuit common legitimate widgets (Google Tag Manager,
// Cloudflare CDN, Stripe) without parsing the URL. Only unknown hosts
// are subjected to the attack-indicator analysis.
func isAttackerScriptURL(rawURL string) bool {
	if isSafeScriptDomain(rawURL) {
		return false
	}
	bad, _ := scriptSrcMaliciousReason(rawURL)
	return bad
}

// isAttackerScriptURLInPost is the caller-facing predicate for
// post_content classification. It uses scriptSrcStrongReason, which
// omits the plaintext-HTTP indicator: legacy author embeds from the
// pre-TLS era are legitimate content, not injection, and must not
// produce db_post_injection findings.
//
// Fresh attacker injections still flag because they almost always point
// at structural markers (raw IP hosts, abused TLDs, cheap exfil hosts)
// rather than at an unremarkable mainstream-TLD host — and an attacker
// who did somehow land on a plaintext-HTTP mainstream host URL would
// still be caught by other checks (obfuscated_php_realtime scanning the
// attacker's dropper, remote payload URLs in the served page, etc.).
func isAttackerScriptURLInPost(rawURL string) bool {
	if isSafeScriptDomain(rawURL) {
		return false
	}
	bad, _ := scriptSrcStrongReason(rawURL)
	return bad
}
