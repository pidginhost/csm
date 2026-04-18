package checks

import (
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// Contract for spam-context analysis
//
// contentHasSpamContext inspects a post body for a spam keyword AND a
// surrounding cloaking/injection signal. A bare keyword mention in
// prose ("our clients include oil and gas, pharma") does not fire; a
// keyword inside an off-screen absolute-positioned div, or next to an
// injection-fingerprint hex comment, or inside an anchor pointing at an
// external URL whose path contains the keyword, does fire.
//
// Tests pin the real-world distinction between legitimate mentions
// (false positives under the earlier substring/word-boundary checks)
// and actual cloaked spam (the lalimanro attack captured in production).
// -----------------------------------------------------------------------------

// Small helper: pull the pattern entry out of dbSpamPatterns so the
// tests stay grounded in the real production catalog.
func spamPattern(t *testing.T, keyword string) dbSpamPattern {
	t.Helper()
	for _, p := range dbSpamPatterns {
		if p.keyword == keyword {
			return p
		}
	}
	t.Fatalf("no spam pattern for keyword %q", keyword)
	return dbSpamPattern{}
}

// -----------------------------------------------------------------------------
// contentHasSpamContext — true positives from production
// -----------------------------------------------------------------------------

func TestContentHasSpamContext_LalimanroCloakedLink(t *testing.T) {
	// Real production attack captured on 2026-04-16: post 14954 "GALERIE"
	// in the lalimanro site. Hidden off-screen div with an anchor to a
	// Romanian pharmacy's viagra product page. Bracketed by a random
	// hex comment the attacker uses as an injection fingerprint.
	content := `<div style="position:absolute;left:-12623px;width:1000px">` +
		`<a href="https://farmaciamillefolia.ro/produs/viagra/">Viagra</a>` +
		`</div><!--44b51-->`
	if !contentHasSpamContext(content, spamPattern(t, "viagra")) {
		t.Fatalf("lalimanro cloaked viagra link must fire as spam context")
	}
}

func TestContentHasSpamContext_DisplayNoneCloaking(t *testing.T) {
	content := `<p>Buy <a href="https://pharma-spam.xyz/">cheap pharma deals</a>` +
		` <span style="display:none">pharma pharma pharma</span></p>`
	if !contentHasSpamContext(content, spamPattern(t, "pharma")) {
		t.Fatalf("display:none cloaked pharma block must fire")
	}
}

func TestContentHasSpamContext_VisibilityHiddenCloaking(t *testing.T) {
	content := `<div style="visibility:hidden">cialis sale here</div>`
	if !contentHasSpamContext(content, spamPattern(t, "cialis")) {
		t.Fatalf("visibility:hidden cloaked cialis must fire")
	}
}

func TestContentHasSpamContext_TextIndentCloaking(t *testing.T) {
	// Classic SEO hide: text-indent: -9999px pushes text off-screen.
	content := `<p style="text-indent:-9999px">viagra generic discount</p>`
	if !contentHasSpamContext(content, spamPattern(t, "viagra")) {
		t.Fatalf("text-indent:-9999px cloaked viagra must fire")
	}
}

func TestContentHasSpamContext_MicroHeightCloaking(t *testing.T) {
	content := `<div style="height:1px;overflow:hidden">betting deals online</div>`
	if !contentHasSpamContext(content, spamPattern(t, "betting")) {
		t.Fatalf("height:1px overflow cloaked betting must fire")
	}
}

func TestContentHasSpamContext_FontSizeZeroCloaking(t *testing.T) {
	content := `<span style="font-size:0">pharma discount codes inside</span>`
	if !contentHasSpamContext(content, spamPattern(t, "pharma")) {
		t.Fatalf("font-size:0 cloaked pharma must fire")
	}
}

func TestContentHasSpamContext_InjectionFingerprintHexComment(t *testing.T) {
	// Attackers leave short hex HTML comments to identify their own
	// injections across a campaign. The fingerprint alone, bracketing
	// a keyword, is a strong signal even without overt CSS cloaking.
	content := `<p><!--44b51-->Get cheap viagra delivered overnight<!--44b51--></p>`
	if !contentHasSpamContext(content, spamPattern(t, "viagra")) {
		t.Fatalf("hex-comment injection fingerprint bracketing viagra must fire")
	}
}

func TestContentHasSpamContext_ExternalAnchorWithKeywordInURL(t *testing.T) {
	// An <a> pointing at an external host whose URL path itself
	// contains the keyword ("/produs/viagra/") is a strong spam signal
	// even without CSS cloaking — site owners do not link spam-category
	// URLs from their content.
	content := `<p>Some text and <a href="https://spam-pharmacy.xyz/buy/pharma/cheap">here</a> more text</p>`
	if !contentHasSpamContext(content, spamPattern(t, "pharma")) {
		t.Fatalf("external anchor with keyword in URL path must fire")
	}
}

func TestContentHasSpamContext_NegativeLeftMargin(t *testing.T) {
	// Variant of absolute-positioned off-screen via margin-left.
	content := `<div style="margin-left:-9999px">cialis cheap</div>`
	if !contentHasSpamContext(content, spamPattern(t, "cialis")) {
		t.Fatalf("margin-left negative off-screen cialis must fire")
	}
}

// -----------------------------------------------------------------------------
// contentHasSpamContext — false positives (must NOT fire)
// -----------------------------------------------------------------------------

func TestContentHasSpamContext_DssolLegitimatePharmaVertical(t *testing.T) {
	// Real production FP from post-patch scan 2026-04-16: dssol page 3161
	// "Dispozitive de identificare si sisteme de marcare". Mentions
	// "Pharma" as an industry vertical the company serves. Red heading
	// style, no cloaking, no external link.
	content := `<span style="color: #ff0000;">Industria alimentara si a bauturilor si Pharma</span>` +
		"\n" + `Alimentele, bauturile, produsele farmaceutice si produsele de consum a`
	if contentHasSpamContext(content, spamPattern(t, "pharma")) {
		t.Fatalf("legitimate Pharma industry-vertical mention must not fire")
	}
}

func TestContentHasSpamContext_HospitalitycultAdvisorBio(t *testing.T) {
	// Real production FP: advisor bio listing industry verticals.
	content := `<p>He has advised clients across consumer goods, steel, energy, ` +
		`telecommunications, oil and gas, pharma.</p>`
	if contentHasSpamContext(content, spamPattern(t, "pharma")) {
		t.Fatalf("legitimate pharma-as-industry-vertical in advisor bio must not fire")
	}
}

func TestContentHasSpamContext_RomanianSpecialistProse(t *testing.T) {
	// Romanian prose mentioning "Specialistii" — the original substring
	// FP was already handled by word boundaries, but prose MUST also
	// pass the context check when other keywords appear without
	// cloaking.
	content := `<p>Pagina aceasta este despre betting responsabil si riscurile asociate.` +
		` Specialistii nostri recomanda moderatia.</p>`
	if contentHasSpamContext(content, spamPattern(t, "betting")) {
		t.Fatalf("prose discussion of betting (no cloaking) must not fire")
	}
}

func TestContentHasSpamContext_KeywordInProseWithColoredSpan(t *testing.T) {
	// Colored text for emphasis is not cloaking — visitors see it.
	content := `<p>Our advisor Răzvan covers <span style="color:#cc0033;font-weight:bold">pharma</span> industry clients.</p>`
	if contentHasSpamContext(content, spamPattern(t, "pharma")) {
		t.Fatalf("bold colored pharma emphasis must not fire")
	}
}

func TestContentHasSpamContext_InternalAnchorWithKeywordNotSpam(t *testing.T) {
	// A link to a page on the SAME site's category "pharma-industry"
	// is not spam; only external anchors with keyword in URL count.
	// The analyzer distinguishes based on scheme + host presence.
	content := `<p>Read more about our <a href="/services/pharma-industry/">pharma</a> clients.</p>`
	if contentHasSpamContext(content, spamPattern(t, "pharma")) {
		t.Fatalf("relative-URL anchor with pharma in path must not fire (internal navigation)")
	}
}

func TestContentHasSpamContext_CloakingFarFromKeyword(t *testing.T) {
	// Cloaking at the very top of a long post, keyword in prose at the
	// bottom. Proximity window prevents spurious association.
	hiddenHeader := `<div style="display:none">legal notice placeholder</div>`
	filler := strings.Repeat(`<p>Some article text goes here with general content.</p>`, 40)
	endProse := `<p>Our industry coverage: consumer goods, steel, energy, oil and gas, pharma.</p>`
	content := hiddenHeader + filler + endProse
	if contentHasSpamContext(content, spamPattern(t, "pharma")) {
		t.Fatalf("cloaking far from keyword must not associate; window must be bounded")
	}
}

func TestContentHasSpamContext_KeywordOnlyNoContext(t *testing.T) {
	// Bare keyword in plain prose — the historical FP pattern on
	// Romanian/English business sites.
	content := `A cialis mention in the middle of neutral text should not fire without context.`
	// The regex DOES match "cialis"; without context it must not fire.
	if contentHasSpamContext(content, spamPattern(t, "cialis")) {
		t.Fatalf("bare keyword without any spam context must not fire")
	}
}

// -----------------------------------------------------------------------------
// contentHasSpamContext — keyword not present at all
// -----------------------------------------------------------------------------

func TestContentHasSpamContext_NoKeywordMatch(t *testing.T) {
	// If the keyword does not appear, no amount of cloaking should
	// fire for that keyword — the function must be keyword-grounded.
	content := `<div style="position:absolute;left:-9999px">hidden marketing text</div>`
	if contentHasSpamContext(content, spamPattern(t, "viagra")) {
		t.Fatalf("no viagra mention present must not fire regardless of cloaking")
	}
}

// -----------------------------------------------------------------------------
// contentHasSpamContext — multiple hits, at least one cloaked
// -----------------------------------------------------------------------------

func TestContentHasSpamContext_AnyCloakedHitFires(t *testing.T) {
	// One legitimate mention + one cloaked mention. Should fire
	// because AT LEAST ONE occurrence has spam context.
	content := `<p>The pharma industry is a key vertical for us.</p>` +
		strings.Repeat(`<p>unrelated body</p>`, 20) +
		`<div style="position:absolute;left:-10000px"><a href="https://evil.xyz/buy/pharma">click</a></div>`
	if !contentHasSpamContext(content, spamPattern(t, "pharma")) {
		t.Fatalf("mixed content with one cloaked pharma hit must fire")
	}
}

// -----------------------------------------------------------------------------
// Regression anchors — internals that are easy to break
// -----------------------------------------------------------------------------

func TestContentHasSpamContext_PositionAbsoluteAloneDoesNotFire(t *testing.T) {
	// position:absolute is common in legitimate CSS (tooltips, menus).
	// It must be paired with a negative coordinate to count as
	// cloaking. This test pins that narrower rule.
	content := `<div style="position:absolute;top:20px;left:50px">pharma industry article</div>`
	if contentHasSpamContext(content, spamPattern(t, "pharma")) {
		t.Fatalf("positive-coordinate absolute-positioned div is not cloaking")
	}
}

func TestContentHasSpamContext_RelativeURLNotExternal(t *testing.T) {
	// href="//example.com/..." IS external (protocol-relative). But
	// href="/path/..." is a same-origin relative URL. Distinguish.
	content := `<a href="/pharma/resources/">read more</a>`
	if contentHasSpamContext(content, spamPattern(t, "pharma")) {
		t.Fatalf("same-origin relative href with keyword in path must not fire")
	}
}

func TestContentHasSpamContext_WhitespaceToleranceInStyle(t *testing.T) {
	// CSS allows whitespace around : and ; — pattern must tolerate it
	// so attackers can't evade with `display : none`.
	content := `<div style="display : none">buy viagra discount</div>`
	if !contentHasSpamContext(content, spamPattern(t, "viagra")) {
		t.Fatalf("whitespace-around-colon display:none must still fire")
	}
}

func TestContentHasSpamContext_CaseInsensitiveCSSDetection(t *testing.T) {
	content := `<DIV STYLE="DISPLAY:NONE">CIALIS SALE</DIV>`
	if !contentHasSpamContext(content, spamPattern(t, "cialis")) {
		t.Fatalf("uppercase CSS cloaking must still fire")
	}
}

func TestContentHasSpamContext_StyleTagRuleSplitEvasion(t *testing.T) {
	// Evasion attempt: attacker splits position:absolute and a negative
	// coordinate across two CSS rules inside a <style> block. A naive
	// pair regex using `[^"'}]*` stops at the first `}` and misses the
	// combination. Both signals still live near the keyword, so the
	// analyser must associate them.
	content := `<style>.a{position:absolute}.b{left:-9999px}</style>` +
		`<div class="a b">buy cheap viagra</div>`
	if !contentHasSpamContext(content, spamPattern(t, "viagra")) {
		t.Fatalf("position:absolute + negative coord split across CSS rules must still fire")
	}
}

func TestContentHasSpamContext_StyleAttrRuleSplitInSeparateAttributes(t *testing.T) {
	// Same evasion logic but via two sibling elements each carrying one
	// half of the cloak. Attacker hides the container, puts the link in
	// a child — still within the proximity window.
	content := `<div style="position:absolute"><span style="left:-12000px">` +
		`<a href="https://spam.top/pharma">pharma</a></span></div>`
	if !contentHasSpamContext(content, spamPattern(t, "pharma")) {
		t.Fatalf("position:absolute + negative left split across sibling style attributes must still fire")
	}
}

// -----------------------------------------------------------------------------
// countCloakedSpamMatches — row aggregator used by checkWPPosts
// -----------------------------------------------------------------------------

func TestCountCloakedSpamMatches_OnlyRowsWithContextCount(t *testing.T) {
	// Three rows: one cloaked attack, two legitimate prose. Only the
	// cloaked one should count — matching the new spam-injection rule.
	rows := []string{
		// Row 1: the lalimanro attack pattern. The URL host and path
		// are intentionally free of "pharma" so that only the viagra
		// keyword fires for this row; we want to isolate row-level
		// attribution in the assertions below.
		`<div style="position:absolute;left:-12623px"><a href="https://spam-site.top/buy/viagra">Viagra</a></div>`,
		// Row 2: dssol-style industry vertical. Bare prose, no spam
		// context — must not count.
		`<p>Industria alimentara si a bauturilor si Pharma</p>`,
		// Row 3: hospitalitycult-style advisor bio prose. Bare prose,
		// no spam context — must not count.
		`<p>Our advisor covers consumer goods, steel, energy, oil and gas, pharma.</p>`,
	}
	if got := countCloakedSpamMatches(spamPattern(t, "viagra"), rows); got != 1 {
		t.Errorf("viagra: got %d cloaked rows, want 1", got)
	}
	if got := countCloakedSpamMatches(spamPattern(t, "pharma"), rows); got != 0 {
		t.Errorf("pharma: got %d cloaked rows, want 0 (rows 2 and 3 are bare prose, row 1 has no pharma)", got)
	}
}

func TestCountCloakedSpamMatches_EmptyContents(t *testing.T) {
	if got := countCloakedSpamMatches(spamPattern(t, "viagra"), nil); got != 0 {
		t.Errorf("nil contents must return 0")
	}
	if got := countCloakedSpamMatches(spamPattern(t, "viagra"), []string{}); got != 0 {
		t.Errorf("empty contents must return 0")
	}
}

func TestCountCloakedSpamMatches_NoKeywordMatches(t *testing.T) {
	rows := []string{
		`<div style="position:absolute;left:-9999px">marketing content</div>`,
		`<p>Our advisor covers consumer goods and energy.</p>`,
	}
	if got := countCloakedSpamMatches(spamPattern(t, "viagra"), rows); got != 0 {
		t.Errorf("rows without any viagra match must count 0")
	}
}

func TestCountCloakedSpamMatches_EachQualifyingRowCountsOnce(t *testing.T) {
	// Even if a row has multiple cloaked keyword hits, it counts once —
	// we are counting distinct POSTS with spam context, not occurrences.
	row := `<div style="display:none">viagra viagra viagra</div>` +
		`<div style="visibility:hidden">more viagra content</div>`
	if got := countCloakedSpamMatches(spamPattern(t, "viagra"), []string{row}); got != 1 {
		t.Errorf("got %d, want 1 (single row counted once despite multiple hits)", got)
	}
}
