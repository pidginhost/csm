package checks

import (
	"fmt"
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
	return []string{"site\tsiteurl\thttps://shop.example", "site\thome\thttps://shop.example"}
}

// The strong signal: an off-canvas container wrapping outbound links.
func TestCheckWPHiddenLinks_OffScreenIsHigh(t *testing.T) {
	posts := []string{
		`148` + "\t" + `<div style="position:absolute;left:-7566px"><a href="https://blck.cl/">x</a></div>`,
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
	posts := []string{`9` + "\t" + `<div style="display:none"><a href="https://partner.example/">x</a></div>`}

	if got := hiddenLinkFindings(t, siteRows(), posts); len(got) != 0 {
		t.Fatalf("single-host display:none reported: %+v", got)
	}
}

// A display:none block pointing at several unrelated domains is a link farm.
func TestCheckWPHiddenLinks_DisplayNoneManyHostsReports(t *testing.T) {
	posts := []string{`9` + "\t" + `<div style="display:none">` +
		`<a href="https://a-one.example/">a</a><a href="https://b-two.example/">b</a></div>`}

	got := hiddenLinkFindings(t, siteRows(), posts)
	if len(got) != 1 {
		t.Fatalf("multi-host hidden block not reported: %+v", got)
	}
}

// Options carry the same injection: scoalataspecial kept CSS-hidden link
// blocks in home_links_custom_* rows, which no post query would ever read.
func TestCheckWPHiddenLinks_ScansOptions(t *testing.T) {
	options := append(siteRows(),
		"opt\thome_links_custom_3\t"+`<div style="text-indent:-9999px"><a href="https://spam.example/">x</a></div>`)

	got := hiddenLinkFindings(t, options, nil)
	if len(got) != 1 {
		t.Fatalf("hidden links in an option row not reported: %+v", got)
	}
	if !strings.Contains(got[0].Details, "home_links_custom_3") {
		t.Errorf("details must name the option row, got:\n%s", got[0].Details)
	}
}

// Without the site's own address every absolute link looks external, so the
// check reports nothing rather than flooding.
func TestCheckWPHiddenLinks_SilentWithoutSiteAddress(t *testing.T) {
	posts := []string{`9` + "\t" + `<div style="left:-9999px;position:absolute"><a href="https://spam.example/">x</a></div>`}

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
	posts := []string{`1` + "\t" + `<div style="left:-12623px;position:absolute">` + anchors.String() + `</div>`}

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
