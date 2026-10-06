package checks

import "testing"

func FuzzHtaccessLegacyPrelude(f *testing.F) {
	f.Add("RewriteRule .* - [E=PHP_VALUE:auto_prepend_file=none]\n")
	f.Add("SetEnv PHP_VALUE \"auto_prepend_file=\\\"/etc/csm/prelude file.php\\\"\"\n")
	f.Add("RewriteRule .* - [E=NOTE:auto_prepend_file='/etc/csm-prelude.php',E=%1:auto_append_file=/tmp/x.php]\n")
	f.Add("RewriteCond %{HTTP:X-N} (.+)\nRewriteRule .* - [E=%1:auto_prepend_file=/tmp/x.php]\n")
	f.Add("php_value auto_prepend_file /home/example/other/wp-content/advanced-headers.php\n")
	f.Add("AddHandler x-custom .haxor .cgix .suspected\n")
	f.Add("AddHandler x-custom HAXOR cgix\n")
	f.Add("AddHandler x-custom .html # .haxor\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, content string) {
		if len(content) > htaccessMaxFileBytes {
			return
		}
		body := []byte(content)
		findings, matches := auditHtaccessLegacyContent("/home/example/public_html/.htaccess", body, htaccessSuspiciousPatterns, htaccessSafePatterns)
		if len(findings) != len(matches) {
			t.Fatalf("findings=%d matches=%d", len(findings), len(matches))
		}
		var ranges []htaccessByteRange
		handlerRanges := make(map[htaccessByteRange]bool)
		for i, match := range matches {
			span := match.Range
			if span.Start < 0 || span.Start >= span.End || span.End > len(body) {
				t.Fatalf("invalid removal span=%+v for %d bytes", span, len(body))
			}
			if span.Start > 0 && body[span.Start-1] != '\n' {
				t.Fatalf("removal starts inside a physical line: %+v", span)
			}
			if findings[i].Check == "htaccess_handler_abuse" {
				if handlerRanges[span] {
					t.Fatalf("duplicate handler finding for range: %+v", span)
				}
				handlerRanges[span] = true
			}
			if !match.Retain {
				ranges = append(ranges, span)
			}
		}
		if cleaned := applyRangeRemoval(body, mergeRanges(ranges)); len(ranges) > 0 && len(cleaned) >= len(body) {
			t.Fatal("removal spans did not remove any bytes")
		}
	})
}
