package checks

import (
	"regexp"
	"strings"
)

// SEO-spam context analysis for WordPress post content.
//
// Word-boundary keyword matching (see countSpamMatches) eliminated the
// substring false positives where "specialist" triggered "cialis" and
// "pharmaceutical" triggered "pharma". It did not eliminate a second
// class of false positive: legitimate prose mentions of an industry or
// product category ("our advisor covers consumer goods, energy,
// pharma" or "Industria alimentara si Pharma"). Word-boundary matching
// cannot distinguish the prose mention from the cloaked black-hat SEO
// link the lalimanro attack injected on the same site.
//
// This file classifies a keyword HIT as SPAM only when the surrounding
// HTML shows an attacker signal: CSS cloaking (off-screen absolute
// positioning, display:none, visibility:hidden, text-indent, micro
// height, font-size:0), an injection fingerprint (short hex HTML
// comment bracketing content), or an external anchor whose URL path
// itself contains the keyword ("/buy/pharma/" style commercial paths).
//
// Bare keyword mentions with none of those signals do not fire, so
// legitimate industry-vertical prose is silent.
//
// The proximity window is bounded to ±spamContextWindow bytes around
// the keyword match. Cloaking at the top of a long post unrelated to
// a keyword mention at the bottom does not spuriously associate.

// spamContextWindow bounds how far (in bytes) around a keyword match
// the analyzer looks for cloaking signals. 400 covers a typical
// cloaked-div attack (small <div> with style + <a> + keyword) without
// reaching into unrelated content.
const spamContextWindow = 400

// cssCloakPatterns are regexes that each, when matched, identify a
// CSS property value indicative of content cloaking. The list is
// conservative: each entry corresponds to a technique widely used in
// real SEO spam campaigns and rarely to nothing else at production
// scale. `(?i)` makes matching case-insensitive; `\s*` around colons
// and values tolerates the whitespace variants attackers use to evade
// naive string scanners ("display : none" vs "display:none").
var cssCloakPatterns = []*regexp.Regexp{
	// display:none and visibility:hidden — classic hide.
	regexp.MustCompile(`(?i)\bdisplay\s*:\s*none\b`),
	regexp.MustCompile(`(?i)\bvisibility\s*:\s*hidden\b`),
	// text-indent with a negative value — pushes text off-screen.
	regexp.MustCompile(`(?i)\btext-indent\s*:\s*-\s*\d+`),
	// Micro height with a positive integer of 0 or 1, paired with
	// overflow:hidden to suppress contents. We require the pair
	// because height:1 alone is occasionally legitimate.
	regexp.MustCompile(`(?i)\bheight\s*:\s*[01](\s*px)?\b[^"'}]*\boverflow\s*:\s*hidden\b`),
	regexp.MustCompile(`(?i)\boverflow\s*:\s*hidden\b[^"'}]*\bheight\s*:\s*[01](\s*px)?\b`),
	// font-size:0 — classic invisible-text technique.
	regexp.MustCompile(`(?i)\bfont-size\s*:\s*0\b`),
	// position:absolute paired with a negative coordinate in the same
	// style attribute (non-greedy [^"'}]* stays inside one attribute).
	// Legitimate uses of position:absolute (menus, tooltips) have
	// non-negative coordinates; the pairing is the signal.
	regexp.MustCompile(`(?i)\bposition\s*:\s*absolute\b[^"'}]*\b(left|top|right|bottom)\s*:\s*-\s*\d+`),
	regexp.MustCompile(`(?i)\b(left|top|right|bottom)\s*:\s*-\s*\d+[^"'}]*\bposition\s*:\s*absolute\b`),
	// Off-screen via large negative margin on a block element.
	regexp.MustCompile(`(?i)\bmargin(-left|-top)?\s*:\s*-\s*\d{4,}`),
}

// injectionFingerprintRe matches the short hex HTML comment (4-8 hex
// chars) attackers use to tag their own injections across a campaign.
// The length bracket is deliberate: shorter matches are too ambiguous,
// longer matches overlap with legitimate WordPress UUIDs.
var injectionFingerprintRe = regexp.MustCompile(`<!--\s*[a-f0-9]{4,8}\s*-->`)

// anchorHrefRe extracts the href attribute value from each anchor tag
// in a fragment. Double- and single-quoted values are both accepted.
var anchorHrefRe = regexp.MustCompile(`(?i)<a\b[^>]+href\s*=\s*["']([^"']+)["']`)

// externalSchemeRe recognises absolute or protocol-relative URLs. A
// relative URL ("/services/pharma/") is same-origin navigation and not
// an external spam link.
var externalSchemeRe = regexp.MustCompile(`^(?i)(https?:)?//`)

// contentHasSpamContext reports whether any occurrence of the keyword
// in content is accompanied by an SEO-spam signal within
// spamContextWindow bytes. Returning false is a direct statement that
// every keyword hit is a bare mention without cloaking context — the
// caller should suppress the finding in that case.
func contentHasSpamContext(content string, pattern dbSpamPattern) bool {
	matches := pattern.regex.FindAllStringIndex(content, -1)
	for _, m := range matches {
		if hitHasSpamContext(content, m[0], m[1], pattern.keyword) {
			return true
		}
	}
	return false
}

// countCloakedSpamMatches returns the number of rows in contents whose
// text contains the spam keyword AND shows an accompanying SEO-spam
// context signal. It is the aggregator used by checkWPPosts to decide
// whether to emit a db_spam_injection finding: bare prose mentions of
// a keyword do not count; only cloaked/SEO-style injections do.
//
// Each qualifying row is counted exactly once regardless of how many
// keyword hits it contains — the finding is per-post, not per-hit.
func countCloakedSpamMatches(pattern dbSpamPattern, contents []string) int {
	n := 0
	for _, c := range contents {
		if contentHasSpamContext(c, pattern) {
			n++
		}
	}
	return n
}

// hitHasSpamContext examines the ±spamContextWindow byte region around
// a single keyword hit for cloaking, injection-fingerprint, or
// external-spam-link signals. Extracted as a helper so tests can target
// one hit at a time.
func hitHasSpamContext(content string, start, end int, keyword string) bool {
	ws := start - spamContextWindow
	if ws < 0 {
		ws = 0
	}
	we := end + spamContextWindow
	if we > len(content) {
		we = len(content)
	}
	window := content[ws:we]

	if windowHasCSSCloaking(window) {
		return true
	}
	if injectionFingerprintRe.MatchString(window) {
		return true
	}
	if windowHasExternalSpamAnchor(window, keyword) {
		return true
	}
	return false
}

// positionAbsoluteRe and negativeCoordRe are evaluated together in
// windowHasCSSCloaking for the "off-screen absolute positioning"
// signal. Keeping them as two independent regexes (rather than one
// paired regex with [^"'}]* between them) closes an evasion where the
// attacker splits the cloak across two CSS rules — e.g.
// `<style>.a{position:absolute}.b{left:-9999px}</style>` — which the
// paired form stops matching at the first `}`. Both signals must
// appear somewhere in the proximity window; the window itself is
// bounded (see spamContextWindow) so the association is not unbounded.
var (
	positionAbsoluteRe = regexp.MustCompile(`(?i)\bposition\s*:\s*absolute\b`)
	negativeCoordRe    = regexp.MustCompile(`(?i)\b(left|top|right|bottom|margin-left|margin-top)\s*:\s*-\s*\d{2,}`)
)

// windowHasCSSCloaking returns true if the window contains any CSS
// declaration from cssCloakPatterns, OR if it contains both
// position:absolute and a negative coordinate somewhere in the window
// (independent-signal form, for rule-split evasions).
func windowHasCSSCloaking(window string) bool {
	for _, re := range cssCloakPatterns {
		if re.MatchString(window) {
			return true
		}
	}
	if positionAbsoluteRe.MatchString(window) && negativeCoordRe.MatchString(window) {
		return true
	}
	return false
}

// windowHasExternalSpamAnchor returns true if the window contains an
// <a href> whose destination is an external URL (absolute or
// protocol-relative) AND whose URL path contains the spam keyword as
// a bounded segment. Same-origin relative links ("/services/pharma/")
// are skipped — they are internal navigation, not spam.
func windowHasExternalSpamAnchor(window, keyword string) bool {
	anchors := anchorHrefRe.FindAllStringSubmatch(window, -1)
	if len(anchors) == 0 {
		return false
	}
	keywordLower := strings.ToLower(keyword)
	for _, a := range anchors {
		href := a[1]
		if !externalSchemeRe.MatchString(href) {
			continue
		}
		if !hrefPathContainsKeyword(href, keywordLower) {
			continue
		}
		return true
	}
	return false
}

// hrefPathContainsKeyword checks whether the URL path portion of href
// contains the keyword bounded by non-alphanumeric characters. The
// boundary guarantees "/buy/pharma/cheap" matches "pharma" but
// "/pharmaceutical/" does not.
func hrefPathContainsKeyword(href, keywordLower string) bool {
	// Strip scheme://host prefix. externalSchemeRe already confirmed
	// the URL starts with //host or scheme://host.
	rest := href
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	} else {
		rest = strings.TrimPrefix(rest, "//")
	}
	// Everything after the first '/' is the path+query.
	var path string
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		path = rest[i:]
	} else {
		path = ""
	}
	lower := strings.ToLower(path)
	idx := strings.Index(lower, keywordLower)
	if idx < 0 {
		return false
	}
	// Check bounded: preceding char (if any) and following char (if
	// any) must not be alphanumeric. This disambiguates
	// "/buy/pharma/" (bounded by '/') from "/pharmacist/" (bounded by
	// 'c' after "pharma").
	if idx > 0 {
		c := lower[idx-1]
		if isURLWordChar(c) {
			return false
		}
	}
	after := idx + len(keywordLower)
	if after < len(lower) {
		c := lower[after]
		if isURLWordChar(c) {
			return false
		}
	}
	return true
}

// isURLWordChar reports whether a byte is an ASCII alphanumeric used
// for URL-path word-boundary analysis. Underscore is treated as a word
// character by convention; hyphen is NOT (so "buy-cheap-pharma" still
// matches "pharma" bounded by the trailing hyphen/slash).
func isURLWordChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '_':
		return true
	}
	return false
}
