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

// scriptSrcMaliciousReason classifies a <script src> URL by attack
// indicators. The first return value is true iff at least one indicator
// fires; the second return value is a short tag suitable for inclusion
// in a finding detail (e.g. "raw IP address", "abused TLD: .top",
// "plaintext HTTP").
//
// The function does not consult knownSafeDomains — callers should do
// that first as a fast path. Separating the two concerns keeps this
// function single-purpose and trivially testable.
func scriptSrcMaliciousReason(rawURL string) (bool, string) {
	// Protocol-relative URLs (//host/path) have to be normalised before
	// url.Parse can extract the host.
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

	// Plaintext HTTP for an external script is a strong indicator.
	// We do not flag https:// nor protocol-relative (which inherits the
	// page's scheme — an https page yields https, an http page already
	// has other problems).
	if strings.EqualFold(u.Scheme, "http") && !strings.HasPrefix(rawURL, "//") {
		return true, "plaintext HTTP external script"
	}

	// Raw IP host (v4 or v6). net.ParseIP accepts both.
	if ip := net.ParseIP(host); ip != nil {
		return true, "raw IP address host"
	}

	// Known bad exfil hosts. Match exact host or any subdomain.
	for _, bad := range knownBadExfilHosts {
		if host == strings.TrimPrefix(bad, ".") {
			return true, "known-bad exfil host: " + bad
		}
		if strings.HasSuffix(host, bad) {
			return true, "known-bad exfil host: " + bad
		}
	}

	// TLD analysis — require at least one dot and a recognisable TLD.
	// Hosts without a dot (e.g. bare "localhost" or "internalhost") do
	// not belong in external <script src>, so flag them.
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

// isAttackerScriptURL is the caller-facing predicate used by
// hasMaliciousExternalScript (in dbscan_filters.go). It combines the
// known-safe fast path with the attack-indicator classifier.
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
