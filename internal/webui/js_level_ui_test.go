package webui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The Web UI ships its scripts without a build step, so what the browser
// runs is what is in the repository. ES2019 is the floor (the runtime
// already relies on Object.fromEntries and Promise.prototype.finally);
// syntax from later editions would stop the page on an older browser that
// otherwise works.
func TestWebUIScriptsStayWithinES2019(t *testing.T) {
	files, err := filepath.Glob("../../ui/static/js/*.js")
	if err != nil {
		t.Fatal(err)
	}
	later := map[string]*regexp.Regexp{
		"optional chaining":     regexp.MustCompile(`[A-Za-z0-9_)\]]\?\.[A-Za-z_$(\[]`),
		"nullish coalescing":    regexp.MustCompile(`\?\?=?\s`),
		"logical assignment":    regexp.MustCompile(`(\|\||&&)=`),
		"numeric separators":    regexp.MustCompile(`\b\d+_\d+\b`),
		"private class members": regexp.MustCompile(`(^|[\s;{])#[A-Za-z_$][\w$]*\s*[=(;]`),
	}
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, ".min.js") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for n, line := range strings.Split(string(src), "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "//") || strings.HasPrefix(code, "*") {
				continue
			}
			for name, re := range later {
				if re.MatchString(line) {
					t.Errorf("%s:%d: %s is newer than ES2019: %s", filepath.Base(file), n+1, name, code)
				}
			}
		}
	}
	if checked < 20 {
		t.Fatalf("checked only %d scripts", checked)
	}
}
