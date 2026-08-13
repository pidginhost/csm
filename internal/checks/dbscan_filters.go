package checks

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// This file contains pure-function helpers used by the database content
// scanner (checkWPPosts in dbscan.go). Keeping them pure (no MySQL, no
// filesystem) makes them deterministically testable and independently
// reusable.
//
// Two classes of false positive were historically observed on real
// production traffic:
//
//  1. db_post_injection fired on every post containing a script tag,
//     including site-owner-added analytics and widget embeds (Google Tag
//     Manager, Google merchant rating badge, etc.).
//
//  2. db_spam_injection used substring LIKE matching, so "specialist"
//     triggered on "cialis", "pharmaceutical" triggered on "pharma",
//     "casino resort" triggered on "casino", etc. It also scanned all
//     post_types including Contact Form 7 / WPForms / Jetpack stored
//     submissions, which routinely contain spambot form fills the site
//     owner never displays.
//
// The helpers below encode the decisions needed to eliminate those FPs
// without opening detection holes: word-boundary keyword matching,
// post_type filtering against a denylist (not an allowlist, so attackers
// cannot hide a post by renaming post_type to one we didn't anticipate),
// and safe-domain filtering for external script-tag sources.

// nonScannablePostTypes are post_type values that legitimately store
// non-site-content data (form submissions, revisions, templates, feeds).
// These are excluded from malware and spam scans because their content
// is operator-invisible storage, not material rendered to site visitors.
//
// This is a DENYLIST, not an allowlist. A custom post_type created by a
// theme or plugin (for example WooCommerce `product`, events, portfolios)
// is still scanned. Adding a new value here is safe; an attacker cannot
// hide a post by choosing a new post_type, because we default to
// scanning anything not on this list.
var nonScannablePostTypes = []string{
	// WordPress internals / templates / navigation
	"revision",
	"customize_changeset",
	"oembed_cache",
	"nav_menu_item",
	"wp_template",
	"wp_template_part",
	"wp_global_styles",
	"wp_navigation",

	// Minification plugins (store compiled bundles that legitimately
	// contain JavaScript and obfuscated character sequences).
	"wphb_minify_group",

	// Form builders (store plugin configuration and visitor submissions.
	// Contact-form spam landing here is noise, not site compromise.)
	"wpforms",
	"wpforms_entries",
	"wpforms-log",
	"wpcf7_contact_form",
	"flamingo_inbound",
	"flamingo_outbound",
	"cf7_message",
	"feedback",
	"jetpack_feedback",
}

// isScannablePostType returns true if the given post_type should be
// included in malware and spam scans. The decision mirrors the SQL
// `post_type NOT IN (...)` clause used in checkWPPosts, so Go-side
// callers and test assertions stay consistent with the live SQL.
func isScannablePostType(postType string) bool {
	for _, t := range nonScannablePostTypes {
		if t == postType {
			return false
		}
	}
	return true
}

// nonScannablePostTypesSQLList returns the denylist as a comma-separated
// SQL literal list (for example "'revision','wp_template',...") suitable
// for use inside a `post_type NOT IN (...)` clause. The values are
// hardcoded and contain only [a-z_-] characters, so SQL injection is not
// a risk here; nonetheless the function escapes defensively.
func nonScannablePostTypesSQLList() string {
	parts := make([]string, 0, len(nonScannablePostTypes))
	for _, t := range nonScannablePostTypes {
		// Hardcoded list contains only [a-z_-], but defensive escape in
		// case future maintainers add a value with a quote or backslash.
		escaped := strings.ReplaceAll(t, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `'`, `\'`)
		parts = append(parts, "'"+escaped+"'")
	}
	return strings.Join(parts, ",")
}

// dbSpamPattern is a single spam-keyword detector. The LIKE fragment
// is a MySQL server-side pre-filter that quickly narrows the set of
// candidate posts; the Go regex finds case-insensitive occurrences and
// spamKeywordMatchIndexes applies strict word boundaries so that
// "specialist" does not match "cialis", "pharmacy" does not match
// "pharma", and so on.
//
// Patterns that end with a non-word character (dash) already have an
// implicit right boundary from that character and only need a left
// word boundary. Patterns ending in a word character need boundaries
// on both sides, even when they contain an internal dash.
type dbSpamPattern struct {
	keyword      string         // human-readable keyword used in finding messages
	regex        *regexp.Regexp // applied Go-side to candidate rows
	likeFragment string         // SQL LIKE fragment, always bracketed with '%'
	// deletable gates the DESTRUCTIVE path only. Scanning uses every
	// pattern; db-clean --delete-spam uses this subset. "pharma" and
	// "betting" are genuine spam keywords that are also ordinary words in
	// legitimate publishing ("Health and Pharma Summit", coverage of a
	// licensed bookmaker), and a word boundary cannot tell the two apart.
	// Flagging those for review is useful; deleting on them is not.
	deletable bool
}

// dbSpamPatterns enumerates the keywords we flag as SEO/pharma/gambling
// spam in WordPress post content. Each entry pairs a fast SQL LIKE with
// a case-insensitive Go regex; spamKeywordMatchIndexes applies the strict
// Unicode word-boundary check.
//
// The regexes are case-insensitive to catch CIALIS / Cialis / cialis.
// The LIKE fragments are lowercase because MySQL LIKE is case-insensitive
// under the default _ci collation used by cPanel MariaDB.
var dbSpamPatterns = []dbSpamPattern{
	newDBSpamPattern("viagra", "%viagra%", true),
	newDBSpamPattern("cialis", "%cialis%", true),
	newDBSpamPattern("pharma", "%pharma%", false),
	newDBSpamPattern("betting", "%betting%", false),
	// Dashed variants: the trailing dash is itself a non-word char and
	// serves as the right boundary. Only a left word-boundary is needed.
	// The dash makes these URL-slug shaped, which prose does not produce,
	// so they carry enough signal to delete on.
	newDBSpamPattern("casino-", "%casino-%", true),
	newDBSpamPattern("buy-cheap-", "%buy-cheap-%", true),
	// These slug forms end in a letter, so the matcher requires both
	// boundaries and rejects longer words such as "free-downloadable".
	newDBSpamPattern("free-download", "%free-download%", true),
	newDBSpamPattern("crack-serial", "%crack-serial%", true),
}

func newDBSpamPattern(keyword, likeFragment string, deletable bool) dbSpamPattern {
	return dbSpamPattern{
		keyword:      keyword,
		regex:        regexp.MustCompile(`(?i)` + regexp.QuoteMeta(keyword)),
		likeFragment: likeFragment,
		deletable:    deletable,
	}
}

// spamKeywordMatchIndexes returns only whole-word keyword matches. Go's \b
// is ASCII-only, so checking adjacent runes explicitly prevents a keyword
// surrounded by non-ASCII letters from being treated as a standalone word.
// A keyword ending in punctuation, such as "casino-", needs no right check:
// the punctuation is already the delimiter that makes the pattern specific.
func spamKeywordMatchIndexes(pattern dbSpamPattern, content string) [][]int {
	matches := pattern.regex.FindAllStringIndex(content, -1)
	confirmed := matches[:0]
	for _, match := range matches {
		if hasSpamWordBoundaries(content, match[0], match[1]) {
			confirmed = append(confirmed, match)
		}
	}
	return confirmed
}

func hasSpamWordBoundaries(content string, start, end int) bool {
	first, _ := utf8.DecodeRuneInString(content[start:end])
	if start > 0 && isSpamWordRune(first) {
		previous, _ := utf8.DecodeLastRuneInString(content[:start])
		if isSpamWordRune(previous) {
			return false
		}
	}

	last, _ := utf8.DecodeLastRuneInString(content[start:end])
	if end < len(content) && isSpamWordRune(last) {
		next, _ := utf8.DecodeRuneInString(content[end:])
		if isSpamWordRune(next) {
			return false
		}
	}
	return true
}

func isSpamWordRune(r rune) bool {
	return r == '_' || r == '\u200c' || r == '\u200d' ||
		r == unicode.ReplacementChar || unicode.IsLetter(r) ||
		unicode.IsNumber(r) || unicode.IsMark(r) || unicode.Is(unicode.Pc, r)
}

// countSpamMatches returns the number of candidate rows with a bounded
// keyword match. The caller is responsible for passing only rows that were
// already narrowed by the pattern.likeFragment SQL pre-filter.
func countSpamMatches(pattern dbSpamPattern, contents []string) int {
	n := 0
	for _, c := range contents {
		if len(spamKeywordMatchIndexes(pattern, c)) > 0 {
			n++
		}
	}
	return n
}

// hasMaliciousExternalScript reports whether the content contains a
// script-tag with a src attribute pointing at a domain NOT on the known-
// safe list (see knownSafeDomains in db_autoresponse.go).
//
// This predicate uses the STRICT classifier (isAttackerScriptURL): it
// flags raw-IP hosts, abused TLDs, known-bad exfil hosts, empty hosts,
// AND plaintext HTTP external scripts. It is the right predicate for
// wp_options and similar configuration storage where fresh-today
// content is expected; see hasMaliciousExternalScriptInPost for the
// looser post_content predicate.
//
// Inline script blocks without a src attribute are not classified by
// this function; those are covered by the separate code-pattern entries
// in dbMalwarePatterns which catch common inline obfuscation techniques.
//
// Rationale: a bare script-tag match was the primary source of false
// positives on real traffic. Legitimate analytics embeds (Google Tag
// Manager, Google Analytics, Google merchant rating badge, Mailchimp,
// HubSpot, etc.) install both an external loader tag AND an inline
// initialization block. Flagging the inline block alone produced many
// HIGH severity noise findings on customer sites. Requiring a
// non-safe-domain external src reduces this to zero FPs in practice
// while still catching attackers who inject a tag pointing at an
// untrusted domain.
func hasMaliciousExternalScript(content string) bool {
	return extractMaliciousScriptURL(content) != ""
}

// hasMaliciousExternalScriptInPost is the post_content variant of
// hasMaliciousExternalScript. It applies the same regex-based script-tag
// extraction but classifies each src URL with isAttackerScriptURLInPost,
// which drops the plaintext-HTTP indicator.
//
// Rationale: post_content carries author-written text that can contain
// pre-TLS-era embeds (e.g. a 2013-era video embed on a Romanian video
// site). Those embeds use http:// and, under the strict classifier,
// would flag on scheme alone even though the post has not been modified
// in a decade. Attackers in 2026 almost never land on plaintext-HTTP
// mainstream-TLD URLs — they use raw IPs, abused TLDs, or cheap exfil
// hosts — so dropping the HTTP signal for this context eliminates the
// legacy-embed false positives without giving up meaningful detection.
func hasMaliciousExternalScriptInPost(content string) bool {
	matches := scriptSrcRe.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		if isAttackerScriptURLInPost(match[1]) {
			return true
		}
	}
	return false
}
