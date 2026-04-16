package checks

import (
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// scriptSrcMaliciousReason — attack-indicator classifier
// -----------------------------------------------------------------------------

func TestScriptSrcMaliciousReason_UnremarkableHostsPass(t *testing.T) {
	// These are the real false-positive cases observed on cluster6:
	// legitimate third-party widgets on mainstream TLDs that were not
	// on the knownSafeDomains allowlist. None has an attack indicator,
	// so the classifier must return false for all.
	cases := []string{
		// OneTrust cookie consent (baxiro post 4084).
		"https://privacyportalde-cdn.onetrust.com/privacy-notice-scripts/otnotice-1.0.min.js",
		// Issuu document embed (dssol post 2012).
		"https://e.issuu.com/embed.js",
		// Romanian video host (filmetaricom posts). HTTP here; see
		// the dedicated plaintext-HTTP test for why we still flag
		// that form separately.
		"https://www.trilulilu.ro/embed-video/floryanplayer/d008a97296f18e",
		// Romanian tax-form widget (radutv post 14953).
		"https://formular230.ro/share/7bffd412e68",
		// Mainstream widgets that the allowlist already covered —
		// should still pass under the new classifier.
		"https://www.googletagmanager.com/gtag/js?id=G-ABC123",
		"https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js",
		"https://js.stripe.com/v3/",
		// Arbitrary but unremarkable .com / .io / .net with reasonable path.
		"https://example.com/widget.js",
		"https://cdn.example.io/lib/main.js",
	}
	for _, c := range cases {
		bad, reason := scriptSrcMaliciousReason(c)
		if bad {
			t.Errorf("expected %q to pass, flagged as %q", c, reason)
		}
	}
}

func TestScriptSrcMaliciousReason_RawIPAddressHost(t *testing.T) {
	cases := []string{
		"https://192.0.2.42/payload.js",
		"https://203.0.113.7/loader.js",
		"https://[2001:db8::1]/payload.js", // IPv6
	}
	for _, c := range cases {
		bad, reason := scriptSrcMaliciousReason(c)
		if !bad {
			t.Errorf("expected raw-IP URL %q to flag", c)
		}
		if !strings.Contains(reason, "IP") {
			t.Errorf("reason should mention IP: %q for %q", reason, c)
		}
	}
}

func TestScriptSrcMaliciousReason_AbusedTLDs(t *testing.T) {
	cases := map[string]string{
		"https://payload.tk/x.js":              "tk",
		"https://attacker.ml/load.js":          "ml",
		"https://evil.ga/p.js":                 "ga",
		"https://spam.cf/j.js":                 "cf",
		"https://host.gq/p.js":                 "gq",
		"https://evil.top/a.js":                "top",
		"https://evil.icu/a.js":                "icu",
		"https://evil.click/x.js":              "click",
		"https://evil.pw/x.js":                 "pw",
		"https://subdomain.attacker.loan/x.js": "loan",
	}
	for u, tld := range cases {
		bad, reason := scriptSrcMaliciousReason(u)
		if !bad {
			t.Errorf("expected abused TLD URL %q to flag", u)
		}
		if !strings.Contains(reason, tld) {
			t.Errorf("reason should mention .%s: %q for %q", tld, reason, u)
		}
	}
}

func TestScriptSrcMaliciousReason_NonAbusedTLDsPass(t *testing.T) {
	// TLDs intentionally NOT on the abused list because of significant
	// legitimate usage. Must NOT flag on TLD alone.
	cases := []string{
		"https://example.xyz/widget.js", // abc.xyz, many startups
		"https://example.online/widget.js",
		"https://example.site/widget.js",
		"https://example.live/widget.js",
		"https://example.space/widget.js",
		"https://example.io/widget.js",
		"https://example.dev/widget.js",
		"https://example.app/widget.js",
	}
	for _, c := range cases {
		bad, reason := scriptSrcMaliciousReason(c)
		if bad {
			t.Errorf("mixed-use TLD %q should not flag on TLD alone; reason=%q", c, reason)
		}
	}
}

func TestScriptSrcMaliciousReason_PlaintextHTTPFlags(t *testing.T) {
	// Plaintext HTTP for an external script is a plaintext-MITM target
	// regardless of destination. Flag on scheme alone.
	bad, reason := scriptSrcMaliciousReason("http://cdn.example.com/lib.js")
	if !bad {
		t.Errorf("expected plaintext HTTP URL to flag")
	}
	if !strings.Contains(strings.ToLower(reason), "plaintext") && !strings.Contains(strings.ToLower(reason), "http") {
		t.Errorf("reason should mention plaintext/HTTP: %q", reason)
	}
}

func TestScriptSrcMaliciousReason_ProtocolRelativeInheritsScheme(t *testing.T) {
	// A protocol-relative URL (//host/path) on an HTTPS page loads over
	// HTTPS. We must NOT flag it just because the URL literal lacks
	// "https:" — otherwise every cached legacy embed fires.
	bad, reason := scriptSrcMaliciousReason("//cdn.example.com/lib.js")
	if bad {
		t.Errorf("protocol-relative URL should not flag on scheme; reason=%q", reason)
	}
}

func TestScriptSrcMaliciousReason_KnownBadExfilHosts(t *testing.T) {
	cases := []string{
		"https://attacker.workers.dev/payload.js",
		"https://pastebin.com/raw/abc123",
		"https://gist.githubusercontent.com/x/y/raw/payload.js",
		"https://bit.ly/xyz",
		"https://tinyurl.com/abc",
	}
	for _, c := range cases {
		bad, _ := scriptSrcMaliciousReason(c)
		if !bad {
			t.Errorf("expected known-bad exfil host URL %q to flag", c)
		}
	}
}

func TestScriptSrcMaliciousReason_HostWithoutTLD(t *testing.T) {
	// localhost, internal hostnames — not valid for external embeds.
	cases := []string{
		"https://localhost/x.js",
		"https://internalhost/x.js",
		"https://myhost/x.js",
	}
	for _, c := range cases {
		bad, _ := scriptSrcMaliciousReason(c)
		if !bad {
			t.Errorf("expected no-TLD host URL %q to flag", c)
		}
	}
}

func TestScriptSrcMaliciousReason_EmptyOrUnparseable(t *testing.T) {
	bad, _ := scriptSrcMaliciousReason("")
	if !bad {
		t.Errorf("empty URL must flag")
	}
	// A URL with no host should flag (relative path that snuck through).
	bad, _ = scriptSrcMaliciousReason("https:///payload.js")
	if !bad {
		t.Errorf("URL with empty host must flag")
	}
}

func TestScriptSrcMaliciousReason_SubdomainsOfAbusedTLDs(t *testing.T) {
	// A deeply-nested subdomain on an abused TLD still flags because
	// the TLD itself is the indicator.
	bad, _ := scriptSrcMaliciousReason("https://a.b.c.evil.tk/x.js")
	if !bad {
		t.Errorf("subdomain on abused TLD must flag")
	}
}

// -----------------------------------------------------------------------------
// isAttackerScriptURL — composed with knownSafeDomains fast path
// -----------------------------------------------------------------------------

func TestIsAttackerScriptURL_SafeDomainFastPath(t *testing.T) {
	// Hosts on knownSafeDomains must short-circuit to "not malicious"
	// regardless of TLD/attack-marker analysis. The allowlist is still
	// useful as an optimization and as a pre-approved operator list.
	cases := []string{
		"https://www.googletagmanager.com/gtag/js",
		"https://cdnjs.cloudflare.com/x.js",
		"https://js.stripe.com/v3/",
		"https://static.hotjar.com/c/hotjar-12345.js",
	}
	for _, c := range cases {
		if isAttackerScriptURL(c) {
			t.Errorf("safe-domain fast path failed for %q", c)
		}
	}
}

func TestIsAttackerScriptURL_ClusterRealFalsePositiveCases(t *testing.T) {
	// The cluster6 FPs from the post-patch scan cycle that drove this
	// rewrite. All must now pass (return false).
	cases := []string{
		// baxiro — OneTrust cookie consent widget.
		"https://privacyportalde-cdn.onetrust.com/privacy-notice-scripts/otnotice-1.0.min.js",
		// dssol — Issuu document embed.
		"//e.issuu.com/embed.js",
		// filmetaricom — trilulilu.ro video embed. The real injection
		// uses http:// which will flag on scheme; legacy posts with
		// https:// should pass.
		"https://www.trilulilu.ro/embed-video/floryanplayer/d008a97296f18e",
		// radutv — formular230.ro widget.
		"https://formular230.ro/share/7bffd412e68",
	}
	for _, c := range cases {
		if isAttackerScriptURL(c) {
			t.Errorf("real cluster6 FP still flagging: %q", c)
		}
	}
}

func TestIsAttackerScriptURL_AttackCasesFlag(t *testing.T) {
	cases := []string{
		"https://evil.tk/payload.js",
		"https://192.0.2.42/load.js",
		"http://cdn.example.com/lib.js", // plaintext HTTP
		"https://attacker.workers.dev/x.js",
		"https://spam.top/loader.js",
	}
	for _, c := range cases {
		if !isAttackerScriptURL(c) {
			t.Errorf("attack case should flag: %q", c)
		}
	}
}

func TestIsAttackerScriptURL_PlaintextHTTPOnTriluliluStillFlagsMindful(t *testing.T) {
	// filmetaricom's posts use http:// (circa 2012 embeds) — these flag
	// under the plaintext-HTTP indicator even though trilulilu.ro
	// itself is not on an abused TLD. This is intended: plaintext HTTP
	// external JS is a MITM vector regardless of destination. The
	// operator should re-embed the content via HTTPS or remove it.
	if !isAttackerScriptURL("http://www.trilulilu.ro/embed-video/x/y") {
		t.Errorf("plaintext HTTP external script should flag even for a mainstream-TLD host")
	}
}

// -----------------------------------------------------------------------------
// abusedTLDs integrity
// -----------------------------------------------------------------------------

func TestAbusedTLDs_NoLeadingDot(t *testing.T) {
	// Entries are stored without the leading dot. A stray "." entry
	// would silently stop matching.
	for tld := range abusedTLDs {
		if strings.HasPrefix(tld, ".") {
			t.Errorf("abused TLD %q must not include leading dot", tld)
		}
		if tld != strings.ToLower(tld) {
			t.Errorf("abused TLD %q must be lowercase", tld)
		}
	}
}

func TestAbusedTLDs_NonEmpty(t *testing.T) {
	if len(abusedTLDs) == 0 {
		t.Fatalf("abused TLD list is empty; detection would silently stop")
	}
	// Sanity: classic Freenom entries must be present.
	for _, tld := range []string{"tk", "ml", "ga", "cf", "gq"} {
		if !abusedTLDs[tld] {
			t.Errorf("abused TLD list missing expected entry %q", tld)
		}
	}
}
