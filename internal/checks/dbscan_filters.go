package checks

import (
	"regexp"
	"strings"
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
// candidate posts; the Go regex then applies a strict word-boundary
// test so that "specialist" does not match "cialis", "pharmacy" does
// not match "pharma", and so on.
//
// Patterns that end with a non-word character (dash) already have an
// implicit right boundary from that character and only need a left
// word boundary. Pure-word patterns need boundaries on both sides.
type dbSpamPattern struct {
	keyword      string         // human-readable keyword used in finding messages
	regex        *regexp.Regexp // applied Go-side to candidate rows
	likeFragment string         // SQL LIKE fragment, always bracketed with '%'
}

// dbSpamPatterns enumerates the keywords we flag as SEO/pharma/gambling
// spam in WordPress post content. Each entry pairs a fast SQL LIKE with
// a strict Go-side word-boundary regex.
//
// The regexes are case-insensitive to catch CIALIS / Cialis / cialis.
// The LIKE fragments are lowercase because MySQL LIKE is case-insensitive
// under the default _ci collation used by cPanel MariaDB.
var dbSpamPatterns = []dbSpamPattern{
	{"viagra", regexp.MustCompile(`(?i)\bviagra\b`), "%viagra%"},
	{"cialis", regexp.MustCompile(`(?i)\bcialis\b`), "%cialis%"},
	{"pharma", regexp.MustCompile(`(?i)\bpharma\b`), "%pharma%"},
	{"betting", regexp.MustCompile(`(?i)\bbetting\b`), "%betting%"},
	// Dashed variants: the trailing dash is itself a non-word char and
	// serves as the right boundary. Only a left word-boundary is needed.
	{"casino-", regexp.MustCompile(`(?i)\bcasino-`), "%casino-%"},
	{"buy-cheap-", regexp.MustCompile(`(?i)\bbuy-cheap-`), "%buy-cheap-%"},
	{"free-download", regexp.MustCompile(`(?i)\bfree-download`), "%free-download%"},
	{"crack-serial", regexp.MustCompile(`(?i)\bcrack-serial`), "%crack-serial%"},
}

// countSpamMatches returns the number of candidate rows whose content
// matches pattern.regex. The caller is responsible for passing only
// rows that were already narrowed by the pattern.likeFragment SQL
// pre-filter; this function applies the strict word-boundary test.
func countSpamMatches(pattern dbSpamPattern, contents []string) int {
	n := 0
	for _, c := range contents {
		if pattern.regex.MatchString(c) {
			n++
		}
	}
	return n
}

// hasMaliciousExternalScript reports whether the content contains a
// script-tag with a src attribute pointing at a domain NOT on the known-
// safe list (see knownSafeDomains in db_autoresponse.go).
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
