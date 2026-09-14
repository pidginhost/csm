package checks

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Three kits on one box wrapped outbound spam links in a container the reader
// never sees: an absolutely positioned block pushed thousands of pixels off the
// canvas, or a display:none wrapper. All of it lived in the database, where the
// file-side spam_hidden_links rules never run.

func TestHiddenOffsiteLinks_OffScreenContainer(t *testing.T) {
	markup := `<div style="position:absolute;left:-12623px;width:1000px">` +
		`<!--44b51--><a href="https://pharma-one.example/x">order</a><!--44b51-->` +
		`<a href="https://pharma-two.example/y">more</a></div>`

	hit := hiddenOffsiteLinks(markup, "shop.example")

	if !hit.offScreen {
		t.Error("a container pushed off the canvas must be graded as off-screen")
	}
	if len(hit.hosts) != 2 {
		t.Fatalf("hosts = %v, want both spam hosts", hit.hosts)
	}
}

// text-indent is the other classic off-canvas trick and carries the same
// meaning as a large negative offset.
func TestHiddenOffsiteLinks_TextIndentOffScreen(t *testing.T) {
	hit := hiddenOffsiteLinks(
		`<p style="text-indent:-9999px"><a href="https://spam.example/">x</a></p>`, "shop.example")

	if !hit.offScreen || len(hit.hosts) != 1 {
		t.Fatalf("text-indent hit = %+v, want off-screen with one host", hit)
	}
}

// Hidden containers are ordinary in real themes -- screen-reader text, mobile
// menus, collapsed panels. Only an outbound link makes one a link injection.
func TestHiddenOffsiteLinks_IgnoresOwnSiteLinks(t *testing.T) {
	markup := `<div style="position:absolute;left:-9999px">` +
		`<a href="https://shop.example/about">about</a>` +
		`<a href="/contact">contact</a></div>`

	if hit := hiddenOffsiteLinks(markup, "shop.example"); len(hit.hosts) != 0 {
		t.Fatalf("own-site links reported as injection: %+v", hit)
	}
}

// A visible container linking off-site is an ordinary outbound link.
func TestHiddenOffsiteLinks_IgnoresVisibleContainer(t *testing.T) {
	markup := `<div style="color:red"><a href="https://partner.example/">partner</a></div>`

	if hit := hiddenOffsiteLinks(markup, "shop.example"); len(hit.hosts) != 0 {
		t.Fatalf("visible outbound link reported: %+v", hit)
	}
}

// display:none hides content without moving it off-canvas, so it is recorded
// but not graded as the off-screen cloak.
func TestHiddenOffsiteLinks_DisplayNoneIsNotOffScreen(t *testing.T) {
	hit := hiddenOffsiteLinks(
		`<div style="display:none"><a href="https://partner.example/">x</a></div>`, "shop.example")

	if hit.offScreen {
		t.Error("display:none must not be graded as an off-canvas cloak")
	}
	if len(hit.hosts) != 1 {
		t.Fatalf("hosts = %v, want the one off-site host", hit.hosts)
	}
}

// The anchor is usually nested several elements below the hidden container.
func TestHiddenOffsiteLinks_FindsNestedAnchors(t *testing.T) {
	markup := `<div style="left:-7566px;position:absolute;top:auto"><ul><li><span>` +
		`<a href="https://blck.cl/">casino online chileno</a></span></li></ul></div>`

	hit := hiddenOffsiteLinks(markup, "shop.example")

	if len(hit.hosts) != 1 || hit.hosts[0] != "blck.cl" {
		t.Fatalf("hosts = %v, want blck.cl from the nested anchor", hit.hosts)
	}
	if !hit.spammy {
		t.Error("gambling vocabulary in the anchor text must be recorded")
	}
}

// Offsets randomize per row, so the grading cannot key on a specific number,
// but a one-pixel nudge is layout, not cloaking.
func TestHiddenOffsiteLinks_SmallOffsetIsNotOffScreen(t *testing.T) {
	hit := hiddenOffsiteLinks(
		`<div style="position:absolute;left:-2px"><a href="https://partner.example/">x</a></div>`,
		"shop.example")

	if hit.offScreen {
		t.Errorf("a -2px offset is layout, not an off-canvas cloak: %+v", hit)
	}
}

// Nesting the injection past a tree parser's open-element limit is a one-line
// evasion, so the scan must still see it -- and must not put attacker-chosen
// nesting on the goroutine stack, where an overflow is fatal and unrecoverable.
func TestHiddenOffsiteLinks_SeesThroughDeepNesting(t *testing.T) {
	deep := strings.Repeat(`<div style="left:-9999px;position:absolute">`, 40000) +
		`<a href="https://spam.example/">x</a>` + strings.Repeat("</div>", 40000)

	hit := hiddenOffsiteLinks(deep, "shop.example")

	if len(hit.hosts) != 1 || hit.hosts[0] != "spam.example" {
		t.Fatalf("hosts = %v, want the link hidden under deep nesting", hit.hosts)
	}
	if !hit.offScreen {
		t.Error("off-canvas styling must survive deep nesting")
	}
}

// Hiding must end where the container does, including when inner tags were
// left unclosed -- otherwise the rest of the page counts as hidden.
func TestHiddenOffsiteLinks_HidingEndsWithTheContainer(t *testing.T) {
	markup := `<div style="display:none"><p>promo</div>` +
		`<a href="https://partner.example/">visible outbound link</a>`

	if hit := hiddenOffsiteLinks(markup, "shop.example"); len(hit.hosts) != 0 {
		t.Fatalf("link after the hidden container reported: %+v", hit)
	}
}

func TestHiddenOffsiteLinks_UnmatchedEndTagDoesNotChangeContainment(t *testing.T) {
	markup := `<section style="display:none"></div>` +
		`<a href="https://partner.example/">partner</a></section>`

	hit := hiddenOffsiteLinks(markup, "shop.example")
	if len(hit.hosts) != 1 || hit.hosts[0] != "partner.example" {
		t.Fatalf("unmatched end tag changed containment: %+v", hit)
	}
}

func TestHiddenOffsiteLinks_AncestorEndClosesNestedHiddenContent(t *testing.T) {
	markup := `<section><div style="display:none"><span></section>` +
		`<a href="https://partner.example/">visible outbound link</a>`

	if hit := hiddenOffsiteLinks(markup, "shop.example"); len(hit.hosts) != 0 {
		t.Fatalf("ancestor end tag left hidden containment open: %+v", hit)
	}
}

func TestHiddenOffsiteLinks_UnclosedAnchorDoesNotConsumeVisibleText(t *testing.T) {
	markup := `<section><div style="display:none">` +
		`<a href="https://partner.example/">partner</section>online casino`

	hit := hiddenOffsiteLinks(markup, "shop.example")
	if len(hit.hosts) != 1 || hit.hosts[0] != "partner.example" {
		t.Fatalf("hidden anchor host = %v, want partner.example", hit.hosts)
	}
	if hit.spammy {
		t.Fatal("an anchor closed by its ancestor consumed later visible spam vocabulary")
	}
}

func TestHiddenOffsiteLinks_NewAnchorClosesHiddenAnchor(t *testing.T) {
	markup := `<a style="display:none" href="https://partner.example/">partner` +
		`<a href="https://other.example/">visible online casino</a>`

	hit := hiddenOffsiteLinks(markup, "shop.example")
	if len(hit.hosts) != 1 || hit.hosts[0] != "partner.example" {
		t.Fatalf("new anchor inherited a closed anchor's hiding: %+v", hit)
	}
	if hit.spammy {
		t.Fatal("new visible anchor text was attributed to the closed hidden anchor")
	}
}

func TestHiddenOffsiteLinks_TracksContainmentPastDepthLimit(t *testing.T) {
	markup := strings.Repeat("<div>", 5000) +
		`<section style="left:-9999px"><a href="https://spam.example/">x</a></section>` +
		strings.Repeat("</div>", 5000)

	hit := hiddenOffsiteLinks(markup, "shop.example")
	if !hit.offScreen || len(hit.hosts) != 1 || hit.hosts[0] != "spam.example" {
		t.Fatalf("deep containment lost the hidden section: %+v", hit)
	}
}

func TestHiddenOffsiteLinks_RawTextCannotCreateMarkup(t *testing.T) {
	for _, element := range []string{"script", "style", "textarea", "title"} {
		t.Run(element, func(t *testing.T) {
			markup := fmt.Sprintf(`<%s><div style="left:-9999px"><a href="https://spam.example/">x</a></div></%s>`,
				element, element)
			if hit := hiddenOffsiteLinks(markup, "shop.example"); len(hit.hosts) != 0 {
				t.Fatalf("markup inside %s created a link hit: %+v", element, hit)
			}
		})
	}
}

func TestHiddenOffsiteLinks_StyleTextIsNotAnInlineDeclaration(t *testing.T) {
	markup := `<style>.promo { left:-9999px }</style>` +
		`<a href="https://partner.example/">visible link</a>`

	if hit := hiddenOffsiteLinks(markup, "shop.example"); len(hit.hosts) != 0 {
		t.Fatalf("style element text hid a visible link: %+v", hit)
	}
}

func TestHiddenOffsiteLinks_RawTextDoesNotSupplyAnchorVocabulary(t *testing.T) {
	markup := `<div style="display:none"><a href="https://partner.example/">` +
		`<script>const category = "online casino";</script>partner</a></div>`

	hit := hiddenOffsiteLinks(markup, "shop.example")
	if len(hit.hosts) != 1 || hit.hosts[0] != "partner.example" {
		t.Fatalf("hidden anchor host = %v, want partner.example", hit.hosts)
	}
	if hit.spammy {
		t.Fatal("script source was treated as rendered anchor text")
	}
}

func TestHiddenOffsiteLinks_FirstDuplicateAttributeWins(t *testing.T) {
	tests := []struct {
		name   string
		markup string
		want   bool
	}{
		{
			name: "first style hidden",
			markup: `<div style="display:none" style="display:block">` +
				`<a href="https://partner.example/">x</a></div>`,
			want: true,
		},
		{
			name: "first style visible",
			markup: `<div style="display:block" style="display:none">` +
				`<a href="https://partner.example/">x</a></div>`,
			want: false,
		},
		{
			name: "first href local",
			markup: `<a style="display:none" href="https://shop.example/" ` +
				`href="https://partner.example/">x</a>`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := len(hiddenOffsiteLinks(tt.markup, "shop.example").hosts) > 0
			if got != tt.want {
				t.Fatalf("hidden link = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestHiddenOffsiteLinks_DecodesStyleEscapes(t *testing.T) {
	styles := []string{
		`display&#58;none`,
		`d&#105;splay:none`,
		`display:n&#111;ne`,
		`d\69splay:none`,
		`display:n\6fne`,
		`left:\2d 9999px`,
	}
	for _, style := range styles {
		t.Run(style, func(t *testing.T) {
			markup := `<div style="` + style + `"><a href="https://partner.example/">x</a></div>`
			hit := hiddenOffsiteLinks(markup, "shop.example")
			if len(hit.hosts) != 1 || hit.hosts[0] != "partner.example" {
				t.Fatalf("escaped style was not applied: %+v", hit)
			}
		})
	}
}

func TestCSSOffScreen_LengthSyntax(t *testing.T) {
	tests := []struct {
		name  string
		style string
		want  bool
	}{
		{name: "em", style: "left:-100em", want: true},
		{name: "rem", style: "left:-100rem", want: true},
		{name: "viewport", style: "left:-1000vw", want: true},
		{name: "percentage", style: "left:-1000%", want: true},
		{name: "important", style: "left:-9999px!important", want: true},
		{name: "simple calc", style: "left:calc(-9999px)", want: true},
		{name: "large exponent", style: "left:-1e400px", want: true},
		{name: "uppercase", style: "LEFT: -9999PX", want: true},
		{name: "small em offset", style: "left:-2em", want: false},
		{name: "small percentage offset", style: "left:-100%", want: false},
		{name: "positive calc", style: "left:calc(9999px)", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseHiddenCSSState(tt.style).offScreen; got != tt.want {
				t.Fatalf("offScreen(%q) = %t, want %t", tt.style, got, tt.want)
			}
		})
	}
}

func TestHiddenOffsiteLinks_UsesEffectiveInlineDeclarations(t *testing.T) {
	tests := []struct {
		name  string
		style string
		want  bool
	}{
		{name: "offset overridden", style: "left:-9999px;left:0", want: false},
		{name: "important offset retained", style: "left:-9999px!important;left:0", want: true},
		{name: "important visible offset", style: "left:-9999px;left:0!important", want: false},
		{name: "hidden overridden", style: "display:none;display:block", want: false},
		{name: "important hidden retained", style: "display:none!important;display:block", want: true},
		{name: "important visible display", style: "display:none;display:block!important", want: false},
		{name: "commented hidden value", style: "display:/* theme fallback */none", want: true},
		{name: "commented offset value", style: "left:/**/-9999px", want: true},
		{name: "decimal zero opacity", style: "opacity:0.0", want: true},
		{name: "leading decimal zero opacity", style: "opacity:.0", want: true},
		{name: "zero percentage opacity", style: "opacity:0%", want: true},
		{name: "negative opacity", style: "opacity:-0.1", want: true},
		{name: "negative percentage opacity", style: "opacity:-10%", want: true},
		{name: "large negative opacity", style: "opacity:-1e400", want: true},
		{name: "nonzero opacity", style: "opacity:0.1", want: false},
		{name: "offset text in URL", style: "background:url('data:image/svg+xml,x;left:-9999px;')", want: false},
		{name: "hidden text in URL", style: "background:url('data:image/svg+xml,x;display:none;')", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			markup := `<div style="` + tt.style + `"><a href="https://partner.example/">x</a></div>`
			got := len(hiddenOffsiteLinks(markup, "shop.example").hosts) == 1
			if got != tt.want {
				t.Fatalf("hidden link for style %q = %t, want %t", tt.style, got, tt.want)
			}
		})
	}
}

func TestHiddenOffsiteLinks_VisibilityCanBeRestoredByDescendant(t *testing.T) {
	markup := `<div style="visibility:hidden"><div style="visibility:visible">` +
		`<a href="https://partner.example/">visible online casino</a></div></div>`

	if hit := hiddenOffsiteLinks(markup, "shop.example"); len(hit.hosts) != 0 {
		t.Fatalf("visibility:visible descendant was treated as hidden: %+v", hit)
	}
}

func TestHiddenOffsiteLinks_UsesRegistrableDomains(t *testing.T) {
	t.Run("own subdomain", func(t *testing.T) {
		markup := `<div style="left:-9999px">` +
			`<a href="https://cdn.shop.example.com/">own CDN</a>` +
			`<a href="https://shop.example.net/">other site</a></div>`
		hit := hiddenOffsiteLinks(markup, "www.shop.example.com")
		if len(hit.hosts) != 1 || hit.hosts[0] != "shop.example.net" {
			t.Fatalf("registrable-domain comparison returned %v", hit.hosts)
		}
	})

	t.Run("IP site", func(t *testing.T) {
		markup := `<div style="left:-9999px">` +
			`<a href="https://192.0.2.1/">own IP</a>` +
			`<a href="https://spam.example/">other site</a></div>`
		hit := hiddenOffsiteLinks(markup, "192.0.2.1")
		if len(hit.hosts) != 1 || hit.hosts[0] != "spam.example" {
			t.Fatalf("IP-site comparison returned %v", hit.hosts)
		}
	})

	t.Run("IDNA aliases", func(t *testing.T) {
		markup := `<div style="left:-9999px">` +
			"<a href=\"https://b\u00fccher.example/\">Unicode</a>" +
			`<a href="https://xn--bcher-kva.example/">ASCII</a></div>`
		hit := hiddenOffsiteLinks(markup, "shop.example")
		if len(hit.hosts) != 1 || hit.hosts[0] != "xn--bcher-kva.example" {
			t.Fatalf("IDNA aliases returned distinct hosts: %v", hit.hosts)
		}
	})
}

func TestHiddenOffsiteLinkSamples_ReassemblesOverlappingBoundedValue(t *testing.T) {
	markup := `<div style="display:none">` + strings.Repeat("x", maxHiddenLinkSampleBytes+1024) +
		`<a href="https://spam.example/">one</a>` +
		`<a href="https://spam.test/">two</a></div>`
	source := hiddenLinkSource{
		markup:     markup[:maxHiddenLinkSampleBytes],
		tailMarkup: markup[len(markup)-maxHiddenLinkSampleBytes:],
		valueBytes: len(markup),
	}

	hit := hiddenOffsiteLinkSamples(source, []string{"shop.example"})
	if len(hit.hosts) != 2 || !hit.multiDomain {
		t.Fatalf("overlapping samples lost hidden containment: %+v", hit)
	}
}

// --- finding construction -------------------------------------------------

func hiddenLinkFindings(t *testing.T, options, posts []string) []alert.Finding {
	t.Helper()
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if strings.Contains(query, "options") {
			return options
		}
		return posts
	}
	t.Cleanup(func() { runMySQLQuery = prev })
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	return checkWPHiddenLinks("alice", creds, "wp_")
}

func siteRows() []string {
	return []string{
		"site\tsiteurl\thttps://shop.example\t\t20\tsite",
		"site\thome\thttps://shop.example\t\t20\tsite",
	}
}

func hiddenLinkPostBatchRow(id, markup string) string {
	head, tail := hiddenLinkBatchSamples(markup)
	return id + "\t" + head + "\t" + tail + "\t" + strconv.Itoa(len(markup)) + "\tpost"
}

func hiddenLinkOptionBatchRow(name, markup string) string {
	head, tail := hiddenLinkBatchSamples(markup)
	return "opt\t" + name + "\t" + head + "\t" + tail + "\t" + strconv.Itoa(len(markup)) + "\topt"
}

func hiddenLinkBatchSamples(value string) (string, string) {
	if len(value) <= maxHiddenLinkSampleBytes {
		return value, value
	}
	return value[:maxHiddenLinkSampleBytes], value[len(value)-maxHiddenLinkSampleBytes:]
}

// The strong signal: an off-canvas container wrapping outbound links.
func TestCheckWPHiddenLinks_OffScreenIsHigh(t *testing.T) {
	posts := []string{
		hiddenLinkPostBatchRow("148", `<div style="position:absolute;left:-7566px"><a href="https://blck.cl/">x</a></div>`),
	}
	got := hiddenLinkFindings(t, siteRows(), posts)

	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %+v", got)
	}
	if got[0].Check != "db_hidden_link_injection" {
		t.Errorf("check = %q", got[0].Check)
	}
	if got[0].Severity != alert.High {
		t.Errorf("severity = %v, want High for an off-canvas container", got[0].Severity)
	}
	if !strings.Contains(got[0].Details, "blck.cl") {
		t.Errorf("details must name the linked domain, got:\n%s", got[0].Details)
	}
}

// display:none plus a single outbound host is what ordinary themes emit, so it
// is not reported on its own.
func TestCheckWPHiddenLinks_DisplayNoneSingleHostStaysSilent(t *testing.T) {
	posts := []string{hiddenLinkPostBatchRow("9", `<div style="display:none"><a href="https://partner.example/">x</a></div>`)}

	if got := hiddenLinkFindings(t, siteRows(), posts); len(got) != 0 {
		t.Fatalf("single-host display:none reported: %+v", got)
	}
}

// A display:none block pointing at several unrelated domains is a link farm.
func TestCheckWPHiddenLinks_DisplayNoneManyHostsReports(t *testing.T) {
	posts := []string{hiddenLinkPostBatchRow("9", `<div style="display:none">`+
		`<a href="https://a-one.example/">a</a><a href="https://b-two.example/">b</a></div>`)}

	got := hiddenLinkFindings(t, siteRows(), posts)
	if len(got) != 1 {
		t.Fatalf("multi-host hidden block not reported: %+v", got)
	}
	if got[0].Severity != alert.Warning {
		t.Fatalf("display:none finding severity = %s, want Warning", got[0].Severity)
	}
}

func TestCheckWPHiddenLinks_DisplayNoneSubdomainsCountOnce(t *testing.T) {
	posts := []string{hiddenLinkPostBatchRow("9", `<div style="display:none">`+
		`<a href="https://a.spam.example/">a</a>`+
		`<a href="https://b.spam.example/">b</a></div>`)}

	if got := hiddenLinkFindings(t, siteRows(), posts); len(got) != 0 {
		t.Fatalf("two hosts on one registrable domain were reported: %+v", got)
	}
}

func TestCheckWPHiddenLinks_DisplayNoneDifferentDomainsReport(t *testing.T) {
	posts := []string{hiddenLinkPostBatchRow("9", `<div style="display:none">`+
		`<a href="https://spam.example/">a</a>`+
		`<a href="https://spam.test/">b</a></div>`)}

	if got := hiddenLinkFindings(t, siteRows(), posts); len(got) != 1 {
		t.Fatalf("two registrable domains produced %d findings, want 1", len(got))
	}
}

func TestCheckWPHiddenLinks_SeparateHiddenContainersDoNotCorroborate(t *testing.T) {
	posts := []string{hiddenLinkPostBatchRow("9", `<div style="display:none">`+
		`<a href="https://partner.example/">a</a></div>`+
		`<div style="display:none"><a href="https://vendor.test/">b</a></div>`)}

	if got := hiddenLinkFindings(t, siteRows(), posts); len(got) != 0 {
		t.Fatalf("separate one-domain containers corroborated one another: %+v", got)
	}
}

// Options carry the same injection: scoalataspecial kept CSS-hidden link
// blocks in home_links_custom_* rows, which no post query would ever read.
func TestCheckWPHiddenLinks_ScansOptions(t *testing.T) {
	options := append(siteRows(), hiddenLinkOptionBatchRow("home_links_custom_3",
		`<div style="text-indent:-9999px"><a href="https://spam.example/">x</a></div>`))

	got := hiddenLinkFindings(t, options, nil)
	if len(got) != 1 {
		t.Fatalf("hidden links in an option row not reported: %+v", got)
	}
	if !strings.Contains(got[0].Details, "home_links_custom_3") {
		t.Errorf("details must name the option row, got:\n%s", got[0].Details)
	}
}

func TestCheckWPHiddenLinks_ScansTrailingSample(t *testing.T) {
	markup := strings.Repeat("x", maxHiddenLinkValueBytes) +
		`<div style="left:-9999px"><a href="https://spam.example/">x</a></div>`
	posts := []string{hiddenLinkPostBatchRow("9", markup)}

	got := hiddenLinkFindings(t, siteRows(), posts)
	if len(got) != 1 || got[0].Severity != alert.High {
		t.Fatalf("hidden link in trailing sample produced %+v, want one High finding", got)
	}
}

func TestCheckWPHiddenLinks_SamplesDoNotShareContainment(t *testing.T) {
	markup := `<div style="display:none"><a href="https://partner.example/">partner` +
		strings.Repeat("x", maxHiddenLinkValueBytes) +
		`<a href="https://other.example/">visible online casino</a>`
	posts := []string{hiddenLinkPostBatchRow("9", markup)}

	if got := hiddenLinkFindings(t, siteRows(), posts); len(got) != 0 {
		t.Fatalf("omitted middle leaked hidden containment into the trailing sample: %+v", got)
	}
}

func TestHiddenLinkOptionRows_PreservesBatchEscapedColumns(t *testing.T) {
	encodedMarkup := `<div style="left:-9999px">line\t2\n<a href="https://spam.example/">x</a></div>`
	wantMarkup := "<div style=\"left:-9999px\">line\t2\n<a href=\"https://spam.example/\">x</a></div>"
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, _ string) []string {
		return []string{
			"opt\thome\\tlinks\\ncustom\t" + encodedMarkup + "\t" + encodedMarkup + "\t" +
				strconv.Itoa(len(wantMarkup)) + "\topt",
			"site\tsiteurl\thttps://shop.example\t\t20\tsite",
		}
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	siteHosts, rows := hiddenLinkOptionRows(wpDBCreds{}, "wp_")
	if len(siteHosts) != 1 || siteHosts[0] != "shop.example" {
		t.Fatalf("site hosts = %v, want shop.example", siteHosts)
	}
	if len(rows) != 1 {
		t.Fatalf("option rows = %d, want 1", len(rows))
	}
	if rows[0].label != "home\tlinks\ncustom" {
		t.Fatalf("option name = %q, batch columns were confused", rows[0].label)
	}
	if rows[0].markup != wantMarkup {
		t.Fatalf("option value = %q, want %q", rows[0].markup, wantMarkup)
	}
}

func TestHiddenLinkOptionRows_FindsSiteRowsAfterCandidateLimit(t *testing.T) {
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, _ string) []string {
		rows := make([]string, maxHiddenLinkRows+1, maxHiddenLinkRows+2)
		for i := range rows {
			rows[i] = hiddenLinkOptionBatchRow(fmt.Sprintf("option_%d", i),
				`<div style="display:none"></div>`)
		}
		return append(rows, "site\tsiteurl\thttps://shop.example\t\t20\tsite")
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	siteHosts, rows := hiddenLinkOptionRows(wpDBCreds{}, "wp_")
	if len(siteHosts) != 1 || siteHosts[0] != "shop.example" {
		t.Fatalf("site hosts after candidate rows = %v, want shop.example", siteHosts)
	}
	if len(rows) != maxHiddenLinkRows {
		t.Fatalf("bounded option rows = %d, want %d", len(rows), maxHiddenLinkRows)
	}
}

func TestHiddenLinkRows_PreserveEmptyTailColumn(t *testing.T) {
	previous := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if strings.Contains(query, "options") {
			return []string{
				"site\tsiteurl\thttps://shop.example\t\t20\tsite",
				"opt\tpromo\t\t\t0\topt",
			}
		}
		return []string{"9\t\t\t0\tpost"}
	}
	t.Cleanup(func() { runMySQLQuery = previous })

	_, options := hiddenLinkOptionRows(wpDBCreds{}, "wp_")
	if len(options) != 1 || options[0].tailMarkup != "" {
		t.Fatalf("option tail = %q in %d rows, want one empty tail", options[0].tailMarkup, len(options))
	}
	posts := hiddenLinkPostRows(wpDBCreds{}, "wp_")
	if len(posts) != 1 || posts[0].tailMarkup != "" {
		t.Fatalf("post tail = %q in %d rows, want one empty tail", posts[0].tailMarkup, len(posts))
	}
}

func TestHiddenLinkOptionRows_MarksOversizeValueIncomplete(t *testing.T) {
	previous := runMySQLQuery
	markup := strings.Repeat("x", maxHiddenLinkValueBytes+1)
	runMySQLQuery = func(_ wpDBCreds, _ string) []string {
		return append(siteRows(), hiddenLinkOptionBatchRow("promo", markup))
	}
	t.Cleanup(func() { runMySQLQuery = previous })

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	_, rows := hiddenLinkOptionRows(wpDBCreds{queryCtx: ctx}, "wp_")
	if len(rows) != 1 {
		t.Fatalf("oversize option rows = %d, want the bounded sample", len(rows))
	}
	if !incomplete.contains("db_content") {
		t.Fatal("oversize option value did not mark the database scan incomplete")
	}
}

func TestHiddenLinkPostRows_MarksOversizeValueIncomplete(t *testing.T) {
	previous := runMySQLQuery
	markup := strings.Repeat("x", maxHiddenLinkValueBytes+1)
	runMySQLQuery = func(_ wpDBCreds, _ string) []string {
		return []string{hiddenLinkPostBatchRow("9", markup)}
	}
	t.Cleanup(func() { runMySQLQuery = previous })

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	rows := hiddenLinkPostRows(wpDBCreds{queryCtx: ctx}, "wp_")
	if len(rows) != 1 {
		t.Fatalf("oversize post rows = %d, want the bounded sample", len(rows))
	}
	if !incomplete.contains("db_content") {
		t.Fatal("oversize post value did not mark the database scan incomplete")
	}
}

func TestHiddenLinkOptionRows_RejectsOversizeSiteAddress(t *testing.T) {
	previous := runMySQLQuery
	var query string
	runMySQLQuery = func(_ wpDBCreds, received string) []string {
		query = received
		return []string{"site\tsiteurl\thttps://shop.example\t\t4097\tsite"}
	}
	t.Cleanup(func() { runMySQLQuery = previous })

	siteHosts, _ := hiddenLinkOptionRows(wpDBCreds{}, "wp_")
	if len(siteHosts) != 0 {
		t.Fatalf("oversize site address supplied local hosts: %v", siteHosts)
	}
	if !strings.Contains(query, "LEFT(CAST(option_value AS BINARY), 4096)") ||
		!strings.Contains(query, "OCTET_LENGTH(option_value)") {
		t.Fatalf("site address query is not byte-bounded: %s", query)
	}
}

func TestCheckWPHiddenLinks_QuotesOptionNameControls(t *testing.T) {
	options := append(siteRows(), hiddenLinkOptionBatchRow("home_links\\nRows: forged",
		`<div style="left:-9999px"><a href="https://spam.example/">x</a></div>`))

	got := hiddenLinkFindings(t, options, nil)
	if len(got) != 1 {
		t.Fatalf("control-character option produced %d findings, want 1", len(got))
	}
	if strings.Contains(got[0].Details, "home_links\nRows: forged") ||
		!strings.Contains(got[0].Details, `home_links\nRows: forged`) {
		t.Fatalf("option name control characters were not quoted: %q", got[0].Details)
	}
}

func TestCheckWPHiddenLinks_QueryIncludesEverySupportedStyle(t *testing.T) {
	prev := runMySQLQuery
	var queries []string
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		queries = append(queries, query)
		if strings.Contains(query, "options") {
			return siteRows()
		}
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	checkWPHiddenLinks("alice", wpDBCreds{}, "wp_")
	if len(queries) != 2 {
		t.Fatalf("queries = %d, want options and posts", len(queries))
	}
	for _, query := range queries {
		for _, want := range []string{
			"LOWER(", "opacity", "calc", "RIGHT(", "OCTET_LENGTH(", "CHAR(92)",
		} {
			if !strings.Contains(query, want) {
				t.Errorf("query missing %q: %s", want, query)
			}
		}
		// Only encoded styles use a guarded regex pass. Ordinary declarations
		// must not spend the server's regex budget on every published post.
		if got := strings.Count(query, "REGEXP"); got != 1 {
			t.Errorf("query has %d regex passes, want the encoded-style pass: %s", got, query)
		}
	}
}

func TestCheckWPHiddenLinks_TreatsHomeAndSiteURLAsLocal(t *testing.T) {
	options := []string{
		"site\thome\thttps://shop.example.com\t\t24\tsite",
		"site\tsiteurl\thttps://admin.example.net\t\t25\tsite",
	}
	posts := []string{hiddenLinkPostBatchRow("9",
		`<div style="left:-9999px"><a href="https://admin.example.net/">admin</a></div>`)}

	if got := hiddenLinkFindings(t, options, posts); len(got) != 0 {
		t.Fatalf("siteurl host was treated as external to the home host: %+v", got)
	}
}

func TestCheckWPHiddenLinks_InvalidSiteAddressCannotWhitelistTarget(t *testing.T) {
	options := []string{
		"site\thome\thttps://shop.example.com\t\t24\tsite",
		"site\tsiteurl\tjavascript://spam.example\t\t25\tsite",
	}
	posts := []string{hiddenLinkPostBatchRow("9",
		`<div style="left:-9999px"><a href="https://spam.example/">spam</a></div>`)}

	got := hiddenLinkFindings(t, options, posts)
	if len(got) != 1 || got[0].Severity != alert.High {
		t.Fatalf("invalid site address suppressed a hidden-link target: %+v", got)
	}
}

// Without the site's own address every absolute link looks external, so the
// check reports nothing rather than flooding.
func TestCheckWPHiddenLinks_SilentWithoutSiteAddress(t *testing.T) {
	posts := []string{hiddenLinkPostBatchRow("9",
		`<div style="left:-9999px;position:absolute"><a href="https://spam.example/">x</a></div>`)}

	if got := hiddenLinkFindings(t, nil, posts); len(got) != 0 {
		t.Fatalf("check ran without knowing the site address: %+v", got)
	}
}

// Without a site address the check must not spend a second query it cannot
// use: every absolute link would look external to it.
func TestCheckWPHiddenLinks_SkipsPostQueryWithoutSiteAddress(t *testing.T) {
	prev := runMySQLQuery
	var queries []string
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		queries = append(queries, query)
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	checkWPHiddenLinks("alice", wpDBCreds{dbName: "wp"}, "wp_")

	if len(queries) != 1 {
		t.Fatalf("ran %d queries without a site address, want only the options read", len(queries))
	}
	if strings.Contains(queries[0], "post_content") {
		t.Errorf("post scan ran before the site address was known: %s", queries[0])
	}
}

// Belt and braces for the same fact one level down: an empty site address must
// not turn every absolute link into an off-site one.
func TestHiddenOffsiteLinks_UnknownSiteHostReportsNothing(t *testing.T) {
	markup := `<div style="position:absolute;left:-9999px"><a href="https://spam.example/">x</a></div>`

	if hit := hiddenOffsiteLinks(markup, ""); len(hit.hosts) != 0 {
		t.Fatalf("unknown site address reported off-site links: %+v", hit)
	}
}

// An operator triaging needs the domains, not "suspicious markup".
func TestCheckWPHiddenLinks_NamesEveryTargetDomain(t *testing.T) {
	var anchors strings.Builder
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&anchors, `<a href="https://farm-%d.example/">l</a>`, i)
	}
	posts := []string{hiddenLinkPostBatchRow("1",
		`<div style="left:-12623px;position:absolute">`+anchors.String()+`</div>`)}

	got := hiddenLinkFindings(t, siteRows(), posts)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %+v", got)
	}
	for _, want := range []string{"farm-0.example", "farm-1.example", "farm-2.example"} {
		if !strings.Contains(got[0].Details, want) {
			t.Errorf("details missing %q, got:\n%s", want, got[0].Details)
		}
	}
}
