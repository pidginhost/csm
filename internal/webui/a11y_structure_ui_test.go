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

// Charts are canvases; each carries a text description.
func TestChartsHaveTextDescriptions(t *testing.T) {
	text := readTemplateText(t, "dashboard")
	for _, id := range []string{"timeline-chart", "attack-types-chart", "trend-chart"} {
		re := regexp.MustCompile(`<canvas id="` + id + `"([^>]*)>`)
		m := re.FindStringSubmatch(text)
		if m == nil || !strings.Contains(m[1], `role="img"`) || !strings.Contains(m[1], `aria-label="`) {
			t.Errorf("%s has no text description: %v", id, m)
		}
	}
}

// Column headers are never empty; an actions column is named for screen
// readers even when it shows no visible label.
func TestTableHeadersAreNamed(t *testing.T) {
	files, err := filepath.Glob("../../ui/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "<th></th>") {
			t.Errorf("%s has an empty column header", filepath.Base(file))
		}
	}
	if strings.Contains(readUIScript(t, "history.js"), "'Time', ''") {
		t.Error("history.js renders an empty column header")
	}
}

// The notifications button says what pressing it will do and whether alerts
// are on.
func TestNotificationButtonReportsItsState(t *testing.T) {
	src := readUIScript(t, "dashboard.js")
	for _, want := range []string{
		"notifBtn.setAttribute('aria-pressed', isActive ? 'true' : 'false');",
		"notifBtn.setAttribute('aria-label', isActive ? 'Disable desktop alerts' : 'Enable desktop alerts');",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("dashboard.js missing %q", want)
		}
	}
}

func TestSkipTargetKeepsAVisibleFocusIndicator(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	rules := regexp.MustCompile(`#csm-main:focus(?:-visible)?\s*\{([^}]+)\}`).FindAllStringSubmatch(string(src), -1)
	visible := false
	for _, rule := range rules {
		if strings.Contains(rule[1], "outline: none") || strings.Contains(rule[1], "outline: 0") {
			t.Fatal("the skip target suppresses its focus indicator")
		}
		visible = visible || strings.Contains(rule[1], "outline:")
	}
	if !visible {
		t.Fatal("the skip target has no visible focus indicator")
	}
}

func TestFindingShortcutDocumentationStaysInOneTable(t *testing.T) {
	src, err := os.ReadFile("../../docs/src/webui.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(src), "### Findings page\n")
	if !ok {
		t.Fatal("missing Findings shortcuts")
	}
	_, table, ok := strings.Cut(section, "|-----|--------|\n")
	if !ok {
		t.Fatal("missing shortcut table")
	}
	for _, key := range []string{"j / k", "o", "d", "f"} {
		rows, _, _ := strings.Cut(table, "\n\n")
		if !strings.Contains(rows, "| `"+key+"`") {
			t.Errorf("%s is outside the shortcuts table", key)
		}
	}
}
