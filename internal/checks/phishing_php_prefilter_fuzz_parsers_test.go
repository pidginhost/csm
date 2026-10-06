package checks

import (
	"strings"
	"testing"
)

func FuzzPHPPhishingPrefilter(f *testing.F) {
	for _, seed := range []string{
		dropboxPhishPHP,
		dottedCapitalIPHPKit,
		phpLibraryBody("Gibt null zurück; ключ не найден.", 2_000),
		"<İNPUT type=password>",
		"$_POKST $_REQUEST <FoRm",
		"x<inpu",
		"\xff<\xc4INPUT",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if mayBePHPPhishing(raw) {
			return
		}
		lower := strings.ToLower(string(raw))
		for _, token := range []string{"$_post", "$_request", "<form", "<input"} {
			if strings.Contains(lower, token) {
				t.Fatalf("prefilter dropped content whose lowercase holds %q: %q", token, raw)
			}
		}
		if res := analyzePHPPhishingContent(string(raw)); res != nil {
			t.Fatalf("prefilter dropped a detection %+v: %q", res, raw)
		}
	})
}
