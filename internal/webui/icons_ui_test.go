package webui

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// An icon class the vendored Tabler Icons font does not define renders as
// nothing, with no error anywhere. Every ti-* name the templates and scripts
// use must exist in the shipped icon stylesheet.
func TestUIIconsExistInIconFont(t *testing.T) {
	css, err := os.ReadFile("../../ui/static/css/tabler-icons.min.css")
	if err != nil {
		t.Fatal(err)
	}
	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`\.ti-([a-z0-9-]+):before`).FindAllStringSubmatch(string(css), -1) {
		defined[m[1]] = true
	}
	if len(defined) < 1000 {
		t.Fatalf("icon stylesheet defines only %d icons", len(defined))
	}
	files, err := filepath.Glob("../../ui/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	scripts, err := filepath.Glob("../../ui/static/js/*.js")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, scripts...)
	use := regexp.MustCompile(`\bti-([a-z0-9]+(?:-[a-z0-9]+)*)`)
	missing := map[string]string{}
	for _, file := range files {
		if strings.HasSuffix(file, ".min.js") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for n, line := range strings.Split(string(src), "\n") {
			if code := strings.TrimSpace(line); strings.HasPrefix(code, "//") || strings.HasPrefix(code, "*") {
				continue
			}
			for _, m := range use.FindAllStringSubmatch(line, -1) {
				if !defined[m[1]] {
					missing[m[1]] = filepath.Base(file) + ":" + strconv.Itoa(n+1)
				}
			}
		}
	}
	var names []string
	for name, where := range missing {
		names = append(names, name+" ("+where+")")
	}
	sort.Strings(names)
	if len(names) > 0 {
		t.Errorf("icons missing from the icon font: %s", strings.Join(names, ", "))
	}
}
