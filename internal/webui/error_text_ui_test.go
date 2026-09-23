package webui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// String(err) already starts with "Error: ", so "'Error: ' + e" showed
// "Error: Error: ...". Pages format a caught error with CSM.errorText.
func TestPagesDoNotPrefixErrorObjects(t *testing.T) {
	files, err := filepath.Glob("../../ui/static/js/*.js")
	if err != nil {
		t.Fatal(err)
	}
	doubled := regexp.MustCompile(`'Error: ?' ?\+ ?(e|err|error)\b|CSM\.toast\([^;]*\+ ?(e|err|error) ?[,)]`)
	for _, file := range files {
		if strings.HasSuffix(file, ".min.js") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for n, line := range strings.Split(string(src), "\n") {
			if doubled.MatchString(line) {
				t.Errorf("%s:%d: error object prefixed with Error: %s", filepath.Base(file), n+1, strings.TrimSpace(line))
			}
		}
	}
}
