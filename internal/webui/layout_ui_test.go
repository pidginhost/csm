package webui

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Stat cards size to their content on wide screens instead of stretching
// across fixed quarter or third columns.
func TestStatCardsUseAutoWidthColumns(t *testing.T) {
	for _, name := range []string{"threat", "rules", "modsec-rules"} {
		text := readTemplateText(t, name)
		if strings.Contains(text, `class="col-sm-6 col-lg-3"`) || regexp.MustCompile(`<div class="col-sm-4"><div class="card">`).MatchString(text) {
			t.Errorf("%s.html stat cards still use fixed columns", name)
		}
		if !strings.Contains(text, `class="col-6 col-lg"`) {
			t.Errorf("%s.html stat cards do not use col-6 col-lg", name)
		}
	}
	if !strings.Contains(readUIScript(t, "dashboard.js"), `'<div class="col-6 col-md-auto me-md-4">'`) {
		t.Error("dashboard challenge stats still spread across the card")
	}
}

// Filters in a card header size to their options; a full-width select
// pushes the other controls onto new lines.
func TestIncidentHeaderSelectsSizeToContent(t *testing.T) {
	text := readTemplateText(t, "incident")
	for _, id := range []string{"incident-status-filter", "incident-page-size", "grouped-status-filter", "grouped-kind-filter", "grouped-page-size"} {
		re := regexp.MustCompile(`<select id="` + id + `" class="([^"]*)"`)
		m := re.FindStringSubmatch(text)
		if m == nil || !strings.Contains(m[1], "csm-auto-width") {
			t.Errorf("%s does not size to its content: %v", id, m)
		}
	}
}

// The grouped view filters on every status the API accepts.
func TestGroupedIncidentsFilterOnEveryStatus(t *testing.T) {
	text := readTemplateText(t, "incident")
	_, block, found := strings.Cut(text, `id="grouped-status-filter"`)
	if !found {
		t.Fatal("no grouped status filter")
	}
	block, _, _ = strings.Cut(block, "</select>")
	for _, status := range []string{"active", "all", "open", "contained", "resolved", "dismissed"} {
		if !strings.Contains(block, `value="`+status+`"`) {
			t.Errorf("grouped status filter lacks %s", status)
		}
	}
}

// Whitelisting and allowing lower protection for an address; their buttons
// use the warning colour, not the green of a safe action.
func TestWhitelistButtonsAreNotGreen(t *testing.T) {
	sources := map[string]string{
		"threat.js":     readUIScript(t, "threat.js"),
		"firewall.js":   readUIScript(t, "firewall.js"),
		"threat.html":   readTemplateText(t, "threat"),
		"firewall.html": readTemplateText(t, "firewall"),
	}
	marker := regexp.MustCompile(`class="btn [^"]*(quick-wl-btn|perm-wl-btn|lookup-whitelist-btn|lookup-allow-btn|fw-whitelist-btn)[^"]*"|id="(bulk-whitelist-btn|trust-submit-btn)"[^>]*|class="btn [^"]*"[^>]*id="(bulk-whitelist-btn|trust-submit-btn)"`)
	found := 0
	for name, text := range sources {
		for _, m := range marker.FindAllString(text, -1) {
			found++
			if strings.Contains(m, "success") {
				t.Errorf("%s: whitelist or allow button is green: %s", name, m)
			}
		}
	}
	if found < 7 {
		t.Fatalf("matched %d whitelist buttons; the markers moved", found)
	}
}

// Every page header uses the same structure: title and subtitle inside
// csm-page-header__main.
func TestPageHeadersShareOneStructure(t *testing.T) {
	for _, name := range []string{"sessions", "verified-bots"} {
		text := readTemplateText(t, name)
		if !strings.Contains(text, `<div class="csm-page-header__main">`) || !strings.Contains(text, `class="csm-page-header__subtitle"`) {
			t.Errorf("%s.html page header does not use the shared structure", name)
		}
	}
}

// Surfaces with their own colours follow the chosen theme instead of
// assuming the dark one.
func TestLightThemeSurfacesFollowTheTheme(t *testing.T) {
	css, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	block := func(selector string) string {
		text := string(css)
		_, rest, ok := strings.Cut(text, selector+" {")
		if !ok {
			t.Fatalf("no %s rule", selector)
		}
		body, _, _ := strings.Cut(rest, "}")
		return body
	}
	if sel := block(".csm-palette__row.is-selected"); strings.Contains(sel, "#fff") {
		t.Error("selected palette row forces white text, unreadable in the light theme")
	}
	undo := block(".csm-undo-banner")
	if !strings.Contains(undo, "var(--csm-bg-card)") || !strings.Contains(undo, "var(--csm-text)") {
		t.Error("undo banner does not use the theme colours")
	}
	login := readTemplateText(t, "login")
	if !strings.Contains(login, `{{asset "js/theme-init.js"}}`) || strings.Contains(login, `class="theme-dark`) {
		t.Error("login page does not follow the chosen theme")
	}
}
