package checks

import (
	"regexp"
	"testing"
)

func FuzzFilesMatchNamesNoFile(f *testing.F) {
	for _, pattern := range []string{"^()$", "^(?:|)$", "^()|()$", "^(:)$", "^($", ""} {
		f.Add(pattern, "asset.css")
	}
	f.Fuzz(func(t *testing.T, pattern, filename string) {
		if !filesMatchNamesNoFile(pattern) {
			return
		}
		re, err := regexp.Compile(pattern)
		if err != nil || !re.MatchString("") {
			t.Fatalf("pattern %q is not a valid empty-name expression", pattern)
		}
		if filename != "" && re.MatchString(filename) {
			t.Fatalf("pattern %q matches nonempty filename %q", pattern, filename)
		}
	})
}

func FuzzRewriteOffShieldRanges(f *testing.F) {
	f.Add(rewriteOffShieldTemplate)
	f.Add("# example \\\n<FilesMatch \"^()$\">\nAllow from all\n</FilesMatch>\n")
	f.Add("<IfModule mod_rewrite.c>\n" + rewriteOffShieldTemplate + "</IfModule>\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, content string) {
		body := []byte(content)
		matches := detectRewriteOffShield(body, ".htaccess")
		for _, m := range matches {
			if m.Range.Start < 0 || m.Range.End < m.Range.Start || m.Range.End > len(body) {
				t.Fatalf("invalid removal range %+v for %d bytes", m.Range, len(body))
			}
		}
		cleaned := applyRangeRemoval(body, mergeRanges(matchRanges(matches)))
		if len(matches) != 0 && len(cleaned) >= len(body) {
			t.Fatal("reported ranges removed no bytes")
		}
	})
}
