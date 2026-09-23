package webui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// Every form control and icon-only button has a name a screen reader can
// announce: an aria-label, a <label for>, or an enclosing <label> with text.
// A placeholder is not a name; it disappears once the field has a value.
func TestTemplateControlsHaveNames(t *testing.T) {
	files, err := filepath.Glob("../../ui/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := html.Parse(strings.NewReader(string(src)))
		if err != nil {
			t.Fatal(err)
		}
		labelled := map[string]bool{}
		var collect func(*html.Node)
		collect = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "label" {
				if f := attr(n, "for"); f != "" {
					labelled[f] = true
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				collect(c)
			}
		}
		collect(doc)
		var check func(*html.Node, bool)
		check = func(n *html.Node, inLabel bool) {
			// Hidden from assistive technology on purpose, such as a
			// select that only backs a row of buttons.
			if n.Type == html.ElementNode && attr(n, "aria-hidden") == "true" {
				return
			}
			if n.Type == html.ElementNode {
				switch n.Data {
				case "label":
					inLabel = inLabel || strings.TrimSpace(textOf(n)) != ""
				case "input", "select", "textarea":
					if attr(n, "type") != "hidden" && attr(n, "aria-label") == "" && attr(n, "aria-labelledby") == "" &&
						!labelled[attr(n, "id")] && !inLabel {
						t.Errorf("%s: %s id=%q has no accessible name", filepath.Base(file), n.Data, attr(n, "id"))
					}
				case "button":
					if strings.TrimSpace(textOf(n)) == "" && attr(n, "aria-label") == "" && attr(n, "aria-labelledby") == "" {
						t.Errorf("%s: icon-only button id=%q class=%q has no aria-label", filepath.Base(file), attr(n, "id"), attr(n, "class"))
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				check(c, inLabel)
			}
		}
		check(doc, false)
	}
}

// Controls the pages render from scripts follow the same rule.
func TestScriptRenderedControlsHaveNames(t *testing.T) {
	files, err := filepath.Glob("../../ui/static/js/*.js")
	if err != nil {
		t.Fatal(err)
	}
	checkbox := regexp.MustCompile(`<input type="checkbox"[^>]*>`)
	iconButton := regexp.MustCompile(`<button[^>]*>\s*<i class="ti [^"]*"( aria-hidden="true")?></i>\s*</button>`)
	for _, file := range files {
		if strings.HasSuffix(file, ".min.js") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for n, line := range strings.Split(string(src), "\n") {
			for _, m := range checkbox.FindAllString(line, -1) {
				if !strings.Contains(m, "aria-label") {
					t.Errorf("%s:%d: checkbox without aria-label", filepath.Base(file), n+1)
				}
			}
			for _, m := range iconButton.FindAllString(line, -1) {
				if tag := m[:strings.Index(m, ">")+1]; !strings.Contains(tag, "aria-label") {
					t.Errorf("%s:%d: icon-only button without aria-label", filepath.Base(file), n+1)
				}
			}
		}
	}
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func textOf(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

// A live region is read aloud whenever it changes. Lists and tab panels
// that refresh on a timer, and a clock that ticks every second, would be
// read out again and again; only short status messages are live.
func TestOnlyStatusMessagesAreLiveRegions(t *testing.T) {
	status := map[string]bool{
		"csm-sse-pill": true, "csm-connection-lost": true, "csm-update-banner": true,
		"csm-toasts": true, "scan-status": true,
	}
	files, err := filepath.Glob("../../ui/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	live := regexp.MustCompile(`<[a-z]+[^>]*aria-live="[a-z]+"[^>]*>`)
	id := regexp.MustCompile(`\bid="([^"]+)"`)
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, tag := range live.FindAllString(string(src), -1) {
			m := id.FindStringSubmatch(tag)
			if m == nil || !status[m[1]] {
				t.Errorf("%s: live region that is not a short status message: %s", filepath.Base(file), tag)
			}
		}
	}
}
