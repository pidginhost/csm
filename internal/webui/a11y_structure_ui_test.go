package webui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Keyboard users can skip the sidebar: the first focusable element jumps
// to the main content.
func TestLayoutHasASkipLink(t *testing.T) {
	layout := readTemplateText(t, "layout")
	_, body, _ := strings.Cut(layout, "<body")
	link := regexp.MustCompile(`<a [^>]*href="#csm-main"[^>]*>Skip to content</a>`)
	loc := link.FindStringIndex(body)
	if loc == nil {
		t.Fatal("layout has no skip link to #csm-main")
	}
	if first := regexp.MustCompile(`<(a|button|input|select)\b`).FindStringIndex(body); first == nil || first[0] != loc[0] {
		t.Error("the skip link is not the first focusable element")
	}
	if !strings.Contains(layout, `<main class="page-body" id="csm-main" tabindex="-1">`) {
		t.Error("main content is not the skip link target")
	}
}

// Headings go down one level at a time: the page title is h1 and section
// titles are h2, so screen reader users can navigate the page outline.
func TestSectionHeadingsFollowThePageTitle(t *testing.T) {
	files, err := filepath.Glob("../../ui/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), `<h3 class="card-title"`) {
			t.Errorf("%s: card title is h3 under an h1", filepath.Base(file))
		}
	}
	for _, script := range []string{"account.js", "threat.js"} {
		if strings.Contains(readUIScript(t, script), `<h3 class="card-title"`) {
			t.Errorf("%s: card title is h3 under an h1", script)
		}
	}
	if !strings.Contains(readUIScript(t, "settings.js"), `const h = document.createElement("h2");`) {
		t.Error("settings section title is not h2")
	}
	if strings.Contains(readTemplateText(t, "hardening"), `<h3 class="mb-0" id="score-text">`) {
		t.Error("hardening score is marked up as a heading")
	}
}
