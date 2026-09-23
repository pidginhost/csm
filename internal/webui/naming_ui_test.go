package webui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

func readTemplateText(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile("../../ui/templates/" + name + ".html")
	if err != nil {
		t.Fatal(err)
	}
	return string(src)
}

// A page is called the same in the sidebar, the browser tab and its heading.
func TestPageNamesMatchAcrossNavTitleAndHeading(t *testing.T) {
	layout := readTemplateText(t, "layout")
	navItem := regexp.MustCompile(`(?s)data-csm-route="([a-z-]+)".*?<span class="nav-link-title">([^<]+)</span>`)
	titleRe := regexp.MustCompile(`\{\{define "title"\}\}([^{]*)\{\{end\}\}`)
	headingRe := regexp.MustCompile(`(?s)<h1 class="csm-page-header__title">(.*?)</h1>`)
	tags := regexp.MustCompile(`<[^>]+>|&nbsp;`)
	items := navItem.FindAllStringSubmatch(layout, -1)
	if len(items) < 15 {
		t.Fatalf("found %d sidebar entries", len(items))
	}
	for _, m := range items {
		route, label := m[1], strings.TrimSpace(m[2])
		page := readTemplateText(t, route)
		title := titleRe.FindStringSubmatch(page)
		if title == nil || strings.TrimSpace(title[1]) != label {
			t.Errorf("%s: sidebar says %q, <title> says %v", route, label, title)
		}
		heading := headingRe.FindStringSubmatch(page)
		if heading == nil || strings.TrimSpace(tags.ReplaceAllString(heading[1], "")) != label {
			t.Errorf("%s: sidebar says %q, heading says %v", route, label, heading)
		}
	}
}

// The product is the Continuous Security Monitor everywhere the UI names it.
func TestUINamesTheProductOneWay(t *testing.T) {
	for _, name := range []string{"layout", "login"} {
		text := readTemplateText(t, name)
		if strings.Contains(text, "CSM Security Monitor") {
			t.Errorf("%s.html names the product differently", name)
		}
		if !strings.Contains(text, "Continuous Security Monitor") {
			t.Errorf("%s.html does not name the product", name)
		}
	}
	if !strings.Contains(readTemplateText(t, "layout"), `<span class="csm-sidebar-brand-rest">Continuous Security Monitor</span>`) {
		t.Error("sidebar brand does not carry the product name")
	}
}

// The firewall's second allow mode is the threat whitelist; it is named so.
func TestFirewallCallsTheWhitelistAWhitelist(t *testing.T) {
	for _, text := range []string{readTemplateText(t, "firewall"), readUIScript(t, "firewall.js")} {
		for _, old := range []string{"Trusted IP", "trusted IP", "Trust IP", "trusted IPs"} {
			if strings.Contains(text, old) {
				t.Errorf("firewall still says %q", old)
			}
		}
	}
	if !strings.Contains(readTemplateText(t, "firewall"), `<option value="trusted">Whitelist</option>`) {
		t.Error("whitelist mode not labelled Whitelist")
	}
}

// /blocked was the Firewall page's old address. It redirects, so the
// address bar and the sidebar show where the operator is.
func TestBlockedRedirectsToFirewall(t *testing.T) {
	s := newTestServer(t, "tok")
	for path, want := range map[string]string{
		"/blocked":              "/firewall",
		"/blocked?ip=192.0.2.4": "/firewall?ip=192.0.2.4",
	} {
		w := httptest.NewRecorder()
		s.handleBlockedRedirect(w, httptest.NewRequest("GET", path, nil))
		if w.Code != http.StatusFound || w.Header().Get("Location") != want {
			t.Errorf("%s -> %d %q, want 302 %q", path, w.Code, w.Header().Get("Location"), want)
		}
	}
}
