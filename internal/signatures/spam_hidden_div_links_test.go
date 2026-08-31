package signatures

import (
	"strings"
	"testing"
)

// The rule claims a hidden div packed with spam links. Its anchor repetition
// could not cross the closing tag of a link, so no real markup ever satisfied
// it. Repairing it means matching the link farm without catching the hidden
// menus and share bars that ordinary themes ship, at the same count of eight
// the scheduled-scan rule already uses.

func TestSpamHiddenDivLinks_RealLinkFarm(t *testing.T) {
	s := loadRepoScanner(t)
	mal := []byte(`<div style="display:none">
<a href="https://cheap-pills.example.test/1">buy</a>
<a href="https://cheap-pills.example.test/2">buy</a>
<a href="https://cheap-pills.example.test/3">buy</a>
<a href="https://cheap-pills.example.test/4">buy</a>
<a href="https://cheap-pills.example.test/5">buy</a>
<a href="https://cheap-pills.example.test/6">buy</a>
<a href="https://cheap-pills.example.test/7">buy</a>
<a href="https://cheap-pills.example.test/8">buy</a>
</div>`)
	if !hasRule(s.ScanContent(mal, ".html"), "spam_hidden_div_links") {
		t.Error("spam_hidden_div_links gap: hidden div of off-site links not detected")
	}
	offscreen := []byte(`<div class="x" style="position: absolute; left: -9999px"><a href="http://a.example.test/1">a1</a><a href="http://a.example.test/2">a2</a><a href="http://a.example.test/3">a3</a><a href="http://a.example.test/4">a4</a><a href="http://a.example.test/5">a5</a><a href="http://a.example.test/6">a6</a><a href="http://a.example.test/7">a7</a><a href="http://a.example.test/8">a8</a><a href="http://a.example.test/9">a9</a></div>`)
	if !hasRule(s.ScanContent(offscreen, ".html"), "spam_hidden_div_links") {
		t.Error("spam_hidden_div_links gap: off-screen link farm not detected")
	}
}

func TestSpamHiddenDivLinks_HiddenMenus(t *testing.T) {
	s := loadRepoScanner(t)
	menu := []byte(`<nav class="mobile-menu"><div style="display: none"><a href="/about">About</a><a href="/support">Support</a><a href="/contact">Contact</a></div></nav>`)
	if hasRule(s.ScanContent(menu, ".html"), "spam_hidden_div_links") {
		t.Error("spam_hidden_div_links FP: collapsed mobile menu matched")
	}
	mega := []byte(`<div class="mega" style="visibility:hidden">
<a href="/shop">Shop</a><a href="/blog">Blog</a><a href="/docs">Docs</a>
<a href="/pricing">Pricing</a><a href="/about">About</a><a href="/jobs">Jobs</a>
</div>`)
	if hasRule(s.ScanContent(mega, ".html"), "spam_hidden_div_links") {
		t.Error("spam_hidden_div_links FP: hidden mega menu of internal links matched")
	}
	blogroll := []byte(`<div class="blogroll">
<a href="https://friend1.example.test">One</a><a href="https://friend2.example.test">Two</a>
<a href="https://friend3.example.test">Three</a><a href="https://friend4.example.test">Four</a>
<a href="https://friend5.example.test">Five</a></div>`)
	if hasRule(s.ScanContent(blogroll, ".html"), "spam_hidden_div_links") {
		t.Error("spam_hidden_div_links FP: visible blogroll matched")
	}
	// Themes ship share bars hidden until a post is hovered. Six off-site
	// links is normal for one; a link farm carries more.
	sharebar := []byte(`<div class="share" style="display:none">
<a href="https://facebook.example.test/share?u=%s">facebook</a>
<a href="https://twitter.example.test/share?u=%s">twitter</a>
<a href="https://linkedin.example.test/share?u=%s">linkedin</a>
<a href="https://pinterest.example.test/share?u=%s">pinterest</a>
<a href="https://whatsapp.example.test/share?u=%s">whatsapp</a>
<a href="https://telegram.example.test/share?u=%s">telegram</a>
</div>`)
	if hasRule(s.ScanContent(sharebar, ".html"), "spam_hidden_div_links") {
		t.Error("spam_hidden_div_links FP: hidden social share bar matched")
	}
}

func TestSpamHiddenDivLinks_RequiresEightLinks(t *testing.T) {
	s := loadRepoScanner(t)
	seven := []byte(`<div style="display:none">` + strings.Repeat(
		`<a href="https://spam.example.test/">buy</a>`, 7) + `</div>`)
	if hasRule(s.ScanContent(seven, ".html"), "spam_hidden_div_links") {
		t.Error("spam_hidden_div_links FP: seven links crossed the shared eight-link threshold")
	}
	nonDiv := []byte(`<section style="display:none">` + strings.Repeat(
		`<a href="https://spam.example.test/">buy</a>`, 8) + `</section>`)
	if hasRule(s.ScanContent(nonDiv, ".html"), "spam_hidden_div_links") {
		t.Error("spam_hidden_div_links FP: a hidden non-div container matched the div rule")
	}
}
