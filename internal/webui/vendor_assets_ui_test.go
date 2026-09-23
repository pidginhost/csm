package webui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A sourceMappingURL to a file that is not shipped makes every browser with
// developer tools open ask the daemon for it and log a 404. Vendored bundles
// ship without their maps, so they carry no reference to one.
func TestVendoredAssetsReferenceOnlyShippedMaps(t *testing.T) {
	files, err := filepath.Glob("../../ui/static/js/*.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := filepath.Glob("../../ui/static/css/*.css")
	if err != nil {
		t.Fatal(err)
	}
	ref := regexp.MustCompile(`sourceMappingURL=([^\s*]+)`)
	for _, file := range append(files, css...) {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ref.FindAllStringSubmatch(string(src), -1) {
			if _, err := os.Stat(filepath.Join(filepath.Dir(file), m[1])); err != nil {
				t.Errorf("%s points at %s, which is not shipped", filepath.Base(file), m[1])
			}
		}
	}
}

// Every browser that runs the Web UI reads WOFF2, so the icon font ships in
// that format only; the TrueType and WOFF copies added several megabytes to
// every package. The stylesheet must name only files that exist.
func TestIconFontShipsWOFF2Only(t *testing.T) {
	fonts, err := os.ReadDir("../../ui/static/css/fonts")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fonts {
		if filepath.Ext(f.Name()) != ".woff2" {
			t.Errorf("fonts/%s is not WOFF2", f.Name())
		}
	}
	css, err := os.ReadFile("../../ui/static/css/tabler-icons.min.css")
	if err != nil {
		t.Fatal(err)
	}
	urls := regexp.MustCompile(`url\("?([^")]+)"?\)`).FindAllStringSubmatch(string(css), -1)
	if len(urls) == 0 {
		t.Fatal("the icon stylesheet names no font file")
	}
	for _, m := range urls {
		name := strings.SplitN(strings.TrimPrefix(m[1], "./"), "?", 2)[0]
		if _, err := os.Stat(filepath.Join("../../ui/static/css", name)); err != nil {
			t.Errorf("the icon stylesheet names %s, which is not shipped", name)
		}
	}
}
