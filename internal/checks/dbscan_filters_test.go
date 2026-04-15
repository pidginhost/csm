package checks

import (
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// isScannablePostType
// -----------------------------------------------------------------------------

func TestIsScannablePostType_UserContentIsScanned(t *testing.T) {
	for _, pt := range []string{"post", "page", "product", "portfolio", "event"} {
		if !isScannablePostType(pt) {
			t.Errorf("post_type %q must be scanned (user-visible content)", pt)
		}
	}
}

func TestIsScannablePostType_InternalTypesSkipped(t *testing.T) {
	for _, pt := range []string{
		"revision", "nav_menu_item", "customize_changeset",
		"wp_template", "wp_template_part", "wp_global_styles",
		"wp_navigation", "oembed_cache", "wphb_minify_group",
	} {
		if isScannablePostType(pt) {
			t.Errorf("post_type %q must be skipped (internal WP storage)", pt)
		}
	}
}

func TestIsScannablePostType_FormSubmissionTypesSkipped(t *testing.T) {
	// These are the post_types that caused the original cluster6 false
	// positives: contact-form plugins store spambot submissions here.
	for _, pt := range []string{
		"flamingo_inbound", "flamingo_outbound", "feedback",
		"jetpack_feedback", "wpcf7_contact_form", "cf7_message",
		"wpforms", "wpforms_entries", "wpforms-log",
	} {
		if isScannablePostType(pt) {
			t.Errorf("post_type %q must be skipped (form-submission storage, visitor-supplied)", pt)
		}
	}
}

func TestIsScannablePostType_UnknownTypesScannedByDefault(t *testing.T) {
	// Defense-in-depth: an attacker must not be able to hide a malicious
	// post by coining a post_type we haven't heard of. Unknown types
	// remain in scope.
	for _, pt := range []string{"", "attacker_custom_type", "hidden_payload"} {
		if !isScannablePostType(pt) {
			t.Errorf("unknown post_type %q must still be scanned (denylist not allowlist)", pt)
		}
	}
}

// -----------------------------------------------------------------------------
// nonScannablePostTypesSQLList
// -----------------------------------------------------------------------------

func TestNonScannablePostTypesSQLList_WellFormedAndEscaped(t *testing.T) {
	list := nonScannablePostTypesSQLList()
	if list == "" {
		t.Fatalf("SQL list must be non-empty")
	}
	// Must not contain a bare ' that would break an enclosing IN (...)
	// clause; every single quote must be escaped with backslash or
	// positioned as a value delimiter. The list is of the shape
	// 'a','b','c' so the only single quotes are at value boundaries.
	parts := strings.Split(list, ",")
	for _, p := range parts {
		if !strings.HasPrefix(p, "'") || !strings.HasSuffix(p, "'") {
			t.Errorf("SQL literal %q must be quoted", p)
		}
		// Each literal must match at least one item on the denylist.
		inner := strings.TrimSuffix(strings.TrimPrefix(p, "'"), "'")
		found := false
		for _, want := range nonScannablePostTypes {
			if inner == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SQL list contains unknown value %q", inner)
		}
	}
	// Must enumerate every denylist entry exactly once.
	if len(parts) != len(nonScannablePostTypes) {
		t.Errorf("SQL list has %d parts, want %d (one per denylist entry)",
			len(parts), len(nonScannablePostTypes))
	}
}

func TestNonScannablePostTypesSQLList_EscapesSingleQuote(t *testing.T) {
	// The hardcoded denylist has no single quotes, but future maintainers
	// might add one. Verify the escape by simulating a quote-bearing value.
	saved := nonScannablePostTypes
	nonScannablePostTypes = []string{`evil'type`}
	defer func() { nonScannablePostTypes = saved }()

	got := nonScannablePostTypesSQLList()
	want := `'evil\'type'`
	if got != want {
		t.Errorf("escape test: got %q, want %q", got, want)
	}
}

// -----------------------------------------------------------------------------
// countSpamMatches — real cluster6 false-positive and true-positive samples
// -----------------------------------------------------------------------------

// pick returns the pattern entry for a given keyword.
func pickPattern(t *testing.T, keyword string) dbSpamPattern {
	t.Helper()
	for _, p := range dbSpamPatterns {
		if p.keyword == keyword {
			return p
		}
	}
	t.Fatalf("no pattern for keyword %q", keyword)
	return dbSpamPattern{}
}

func TestCountSpamMatches_CialisNotInSpecialist(t *testing.T) {
	// Real cluster6 false positive: Romanian business content using
	// "Specialistii" / "specialists" triggered the old substring match.
	contents := []string{
		`Specialistii DS Solution au acumulat ani de experienta in programare.`,
		`Our specialists are on call 24/7.`,
		`Pagina despre specialist.`,
	}
	if got := countSpamMatches(pickPattern(t, "cialis"), contents); got != 0 {
		t.Errorf("got %d cialis matches in 'specialist' content, want 0", got)
	}
}

func TestCountSpamMatches_CialisTruePositive(t *testing.T) {
	// Actual spam injection phrasing.
	contents := []string{
		`buy cialis online cheap`,
		`CIALIS generic sale <a href="https://spam.xyz">here</a>`,
		`prescription-free cialis. shipped overnight.`,
	}
	for i, c := range contents {
		if got := countSpamMatches(pickPattern(t, "cialis"), []string{c}); got != 1 {
			t.Errorf("row %d: got %d matches, want 1 (content: %q)", i, got, c)
		}
	}
}

func TestCountSpamMatches_PharmaNotInPharmaceutical(t *testing.T) {
	// Real cluster6 false positive: legitimate olive-oil B2B content
	// mentioning "pharmaceutical" industry.
	contents := []string{
		`supply to the nutraceutical, pharmaceutical, health & wellness industries`,
		`Is Alpha-Olenic Olive Oil a pharmaceutical product?`,
		`Our pharmacy partner handles fulfilment.`,
		`Shop for pharmacist-recommended vitamins.`,
	}
	if got := countSpamMatches(pickPattern(t, "pharma"), contents); got != 0 {
		t.Errorf("got %d pharma matches in 'pharmaceutical/pharmacy' content, want 0", got)
	}
}

func TestCountSpamMatches_PharmaTruePositive(t *testing.T) {
	contents := []string{
		`cheap pharma deals from russia`,
		`Pharma discount codes inside.`,
	}
	for i, c := range contents {
		if got := countSpamMatches(pickPattern(t, "pharma"), []string{c}); got != 1 {
			t.Errorf("row %d: got %d matches, want 1 (content: %q)", i, got, c)
		}
	}
}

func TestCountSpamMatches_CasinoMatchesOnlyDashedSpamDomains(t *testing.T) {
	// Dashed variant: matches casino-spam-domain, not the bare word.
	noMatch := []string{
		`The casino resort "City of Dreams" sits nearby.`,
		`applicants for a license to open a casino in Cyprus`,
		`the upcoming casino resort of Limassol`,
	}
	for i, c := range noMatch {
		if got := countSpamMatches(pickPattern(t, "casino-"), []string{c}); got != 0 {
			t.Errorf("false positive on casino- in real-estate context row %d: content=%q", i, c)
		}
	}

	hasMatch := []string{
		`Visit casino-offers.xyz today`,
		`/casino-spam.com/ is now live`,
		`Click here: https://casino-bonus-codes.ru/`,
	}
	for i, c := range hasMatch {
		if got := countSpamMatches(pickPattern(t, "casino-"), []string{c}); got != 1 {
			t.Errorf("missed true-positive casino- URL row %d: content=%q", i, c)
		}
	}
}

func TestCountSpamMatches_ViagraBoundaries(t *testing.T) {
	// Bare-word viagra — no FP on substring positions inside larger words.
	if got := countSpamMatches(pickPattern(t, "viagra"), []string{"provisioning viagrass"}); got != 0 {
		t.Errorf("got %d viagra matches in 'viagrass' content, want 0", got)
	}
	if got := countSpamMatches(pickPattern(t, "viagra"), []string{"buy viagra online"}); got != 1 {
		t.Errorf("missed real 'buy viagra online' match")
	}
}

func TestCountSpamMatches_BettingBoundaries(t *testing.T) {
	// "abetting" contains "betting" as substring; must not match.
	if got := countSpamMatches(pickPattern(t, "betting"), []string{`aiding and abetting the fraud`}); got != 0 {
		t.Errorf("false positive on 'abetting'")
	}
	if got := countSpamMatches(pickPattern(t, "betting"), []string{"sports betting tips"}); got != 1 {
		t.Errorf("missed real 'sports betting tips' match")
	}
}

func TestCountSpamMatches_CaseInsensitive(t *testing.T) {
	for _, c := range []string{`BUY CIALIS NOW`, `Cialis Generic`, `cIaLiS`} {
		if got := countSpamMatches(pickPattern(t, "cialis"), []string{c}); got != 1 {
			t.Errorf("case-insensitive match failed: %q", c)
		}
	}
}

func TestCountSpamMatches_CountsDistinctRows(t *testing.T) {
	// Each row is counted once, regardless of how many matches it contains.
	rows := []string{
		`cialis cialis cialis`,             // counts 1
		`Specialistii DS Solution`,         // does not count (FP case)
		`another cialis ad`,                // counts 1
		`buy cheap cialis and pharma deal`, // counts 1 for cialis
	}
	if got := countSpamMatches(pickPattern(t, "cialis"), rows); got != 3 {
		t.Errorf("got %d, want 3 (3 distinct cialis rows; 'Specialistii' is FP)", got)
	}
}

func TestCountSpamMatches_AllKeywordsHaveBoundaries(t *testing.T) {
	// Assert every pattern on the list rejects substring-only matches.
	// For each keyword, craft a content string that contains the keyword
	// as a non-word-bounded substring and verify it is NOT matched.
	subStringInjections := map[string]string{
		"viagra":        "sviagraworld",   // no word boundary
		"cialis":        "specialist",     // classic FP
		"pharma":        "pharmaceutical", // classic FP
		"betting":       "abetting",       // classic FP
		"casino-":       "recasino-x",     // left boundary missing ('e' then 'c')
		"buy-cheap-":    "rebuy-cheap-x",  // left boundary missing
		"free-download": "defree-downloadx",
		"crack-serial":  "xcrack-serialx",
	}
	for _, p := range dbSpamPatterns {
		content := subStringInjections[p.keyword]
		if content == "" {
			t.Fatalf("test missing fixture for keyword %q", p.keyword)
		}
		if got := countSpamMatches(p, []string{content}); got != 0 {
			t.Errorf("keyword %q substring-matched %q (want 0 matches)", p.keyword, content)
		}
	}
}

// -----------------------------------------------------------------------------
// hasMaliciousExternalScript — real cluster6 samples
// -----------------------------------------------------------------------------

func TestHasMaliciousExternalScript_GoogleTagManager(t *testing.T) {
	// Real cluster6 FP: lamicutu posts 17587/17588 content (sanitized).
	content := `<script async src="https://www.googletagmanager.com/gtag/js?id=G-J2F8BWG8DF"></script>` +
		`<script>window.dataLayer = window.dataLayer || []; function gtag(){dataLayer.push(arguments);}</script>`
	if hasMaliciousExternalScript(content) {
		t.Errorf("Google Tag Manager embed must NOT flag as malicious")
	}
}

func TestHasMaliciousExternalScript_GoogleMerchantBadge(t *testing.T) {
	// Real cluster6 FP: depo24ro post 12696 content (sanitized).
	content := `<script src="https://apis.google.com/js/platform.js?onload=renderBadge" async defer></script>`
	if hasMaliciousExternalScript(content) {
		t.Errorf("Google merchant rating badge embed must NOT flag as malicious")
	}
}

func TestHasMaliciousExternalScript_CommonWidgets(t *testing.T) {
	cases := []string{
		`<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>`,
		`<script src="https://cdn.jsdelivr.net/npm/react@18/umd/react.production.min.js"></script>`,
		`<script src="https://static.hotjar.com/c/hotjar-12345.js"></script>`,
		`<script src="https://www.google-analytics.com/analytics.js"></script>`,
		`<script src="https://connect.facebook.net/en_US/fbevents.js"></script>`,
		`<script src="https://js.stripe.com/v3/"></script>`,
	}
	for _, c := range cases {
		if hasMaliciousExternalScript(c) {
			t.Errorf("legitimate widget embed must NOT flag: %s", firstLine(c))
		}
	}
}

func TestHasMaliciousExternalScript_AttackerExternalSrc(t *testing.T) {
	cases := []string{
		`<script src="https://evil-cdn.xyz/payload.js"></script>`,
		`<script src='http://cryptomine.su/loader.js'></script>`,
		`<script src="//malware.pw/skim.js" async></script>`,
		`<script type="text/javascript" src="https://attacker.workers.dev/x.js"></script>`,
	}
	for _, c := range cases {
		if !hasMaliciousExternalScript(c) {
			t.Errorf("attacker external script must flag: %s", firstLine(c))
		}
	}
}

func TestHasMaliciousExternalScript_InlineScriptsNotClassified(t *testing.T) {
	// Inline scripts (no src) are not in scope for this classifier;
	// code-pattern entries in dbMalwarePatterns catch the common
	// obfuscation techniques. We verify hasMaliciousExternalScript
	// returns false for well-formed inline scripts (legitimate and
	// suspicious alike — the inline-code classifiers downstream handle
	// those cases).
	cases := []string{
		`<script>window.dataLayer = [];</script>`,
		`<script>var x = atob('aW5saW5lIG9iZnVzY2F0aW9u');</script>`, // inline, no src
		`<script>alert(1)</script>`,
	}
	for _, c := range cases {
		if hasMaliciousExternalScript(c) {
			t.Errorf("inline script (no src) should not be classified here: %s", firstLine(c))
		}
	}
}

func TestHasMaliciousExternalScript_MixedContentFindsRealAttack(t *testing.T) {
	// Legitimate page content plus a single attacker script mixed in.
	content := `<h1>Welcome</h1>` +
		`<script src="https://www.googletagmanager.com/gtag/js"></script>` +
		`<p>About our company...</p>` +
		`<script src="https://evil.xyz/payload.js"></script>` +
		`<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>`
	if !hasMaliciousExternalScript(content) {
		t.Errorf("mixed content with one attacker script must flag")
	}
}

func TestHasMaliciousExternalScript_SubdomainsOfSafeDomainsAllowed(t *testing.T) {
	// Subdomain matching: www.googletagmanager.com, cdnjs.cloudflare.com, etc.
	cases := []string{
		`<script src="https://www.googletagmanager.com/gtag/js"></script>`,
		`<script src="https://cdnjs.cloudflare.com/ajax/libs/x.js"></script>`,
		`<script src="https://prod.hubspot.com/widget.js"></script>`,
	}
	for _, c := range cases {
		if hasMaliciousExternalScript(c) {
			t.Errorf("subdomain of safe domain must NOT flag: %s", firstLine(c))
		}
	}
}

// -----------------------------------------------------------------------------
// regression helpers
// -----------------------------------------------------------------------------

// firstLine returns the first line of a string (trimmed), for concise
// assertion messages.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	return s
}

// Compile-time assertion that the key patterns stay populated so a
// future refactor that accidentally empties the list is caught by CI.
func TestDbSpamPatterns_NonEmpty(t *testing.T) {
	if len(dbSpamPatterns) == 0 {
		t.Fatalf("dbSpamPatterns is empty; detection would silently stop")
	}
	// Every pattern must have all three fields set.
	for i, p := range dbSpamPatterns {
		if p.keyword == "" || p.regex == nil || p.likeFragment == "" {
			t.Errorf("pattern %d is incomplete: %+v", i, p)
		}
		// LIKE fragment must be bracketed with % on both sides so the
		// caller does not need to add them.
		if !strings.HasPrefix(p.likeFragment, "%") || !strings.HasSuffix(p.likeFragment, "%") {
			t.Errorf("pattern %d likeFragment %q must be bracketed with %%", i, p.likeFragment)
		}
	}
}

func TestDbSpamPatterns_RegexesCompile(t *testing.T) {
	// Regexes are compiled at package init via MustCompile; a nil value
	// would panic on use. This test asserts presence of every expected
	// keyword as documentation of the detection catalog.
	want := []string{"viagra", "cialis", "pharma", "betting", "casino-",
		"buy-cheap-", "free-download", "crack-serial"}
	got := map[string]bool{}
	for _, p := range dbSpamPatterns {
		got[p.keyword] = true
	}
	for _, k := range want {
		if !got[k] {
			t.Errorf("dbSpamPatterns missing keyword %q", k)
		}
	}
}

// TestPickPatternSanity ensures the test helper itself is wired correctly.
func TestPickPatternSanity(t *testing.T) {
	p := pickPattern(t, "cialis")
	if p.keyword != "cialis" {
		t.Fatalf("pickPattern returned wrong entry: %+v", p)
	}
}

// TestIsScannablePostType_DocumentedBehavior pins the three canonical
// contributor-facing cases so the logic stays readable by example.
func TestIsScannablePostType_DocumentedBehavior(t *testing.T) {
	cases := map[string]bool{
		"post":             true,
		"flamingo_inbound": false,
		"attacker_custom":  true,
	}
	for pt, want := range cases {
		if got := isScannablePostType(pt); got != want {
			t.Errorf("isScannablePostType(%q) = %v, want %v", pt, got, want)
		}
	}
}
