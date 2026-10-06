package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// phpLibraryBody is shaped like the vendored library code the deep phishing
// walk reads most often: no request superglobals and no form markup.
func phpLibraryBody(comment string, size int) string {
	block := `
	/**
	 * Resolve the cached value for a key. ` + comment + `
	 */
	public function resolve($key, array $options = [])
	{
		if (isset($this->cache[$key])) {
			return $this->cache[$key];
		}
		$value = $this->loader->load($key, $options + $this->defaults);
		return $this->cache[$key] = is_string($value) ? trim($value) : $value;
	}
`
	var b strings.Builder
	b.WriteString("<?php\nnamespace Vendor\\Cache;\n\nclass Resolver\n{\n")
	for b.Len() < size {
		b.WriteString(block)
	}
	b.WriteString("}\n")
	return b.String()
}

func BenchmarkAnalyzePHPForPhishing(b *testing.B) {
	samples := map[string]string{
		"library_ascii": phpLibraryBody("Returns null when missing.", 99_000),
		"library_utf8":  phpLibraryBody("Gibt null zurück, wenn der Schlüssel fehlt; ключ не найден.", 99_000),
		"kit":           dropboxPhishPHP + strings.Repeat("\n<!-- padding -->", 500),
	}
	for name, body := range samples {
		path := filepath.Join(b.TempDir(), name+".php")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			b.Fatal(err)
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				analyzePHPForPhishing(context.Background(), path)
			}
		})
	}
}

// dottedCapitalIPHPKit reaches the HTML form check only through U+0130, which
// strings.ToLower turns into a plain "i": no request superglobal, no "<form",
// and every input tag spelled "<İNPUT".
const dottedCapitalIPHPKit = `<?php
// rendered login
?>
<html><head><title>Dropbox - Sign in</title></head>
<body>
<p>Confirm access to the shared file.</p>
<İNPUT type="email" name="email">
<İNPUT type="password" name="password">
<script>window.location.href = "https://example.test/next";</script>
</body></html>`

func TestPHPPhishingPrefilterTokens(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    bool
	}{
		{"empty", "", false},
		{"library code", phpLibraryBody("Returns null when missing.", 4_000), false},
		{"other superglobals", `<?php echo $_GET['q'] . $_SERVER['HTTP_HOST'] . $_COOKIE['id'];`, false},
		{"tokens split by spaces", "$ _POST < form < input $_ REQUEST", false},
		{"words without anchors", "post request form input", false},
		{"post superglobal", `<?php $e = $_POST['email'];`, true},
		{"request superglobal mixed case", `<?php $e = $_ReQuEsT['email'];`, true},
		{"form tag upper case", "<FORM method=post>", true},
		{"input tag mixed case", "<iNpUt type=password>", true},
		{"post superglobal at end", "x$_post", true},
		{"input tag at end", "x<INPUT", true},
		{"truncated tag at end", "x<inpu", false},
		{"dotted capital I", "<İNPUT type=password>", true},
		{"kelvin sign", "K", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mayBePHPPhishing([]byte(tc.content)); got != tc.want {
				t.Errorf("mayBePHPPhishing(%q) = %t, want %t", tc.content, got, tc.want)
			}
		})
	}
}

// A non-ASCII rune that strings.ToLower turns into ASCII can complete a token
// the byte scan never saw, so every such rune must keep the content.
func TestPHPPhishingPrefilterKeepsRunesLoweredToASCII(t *testing.T) {
	found := 0
	for r := rune(0x80); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		lower := strings.ToLower(string(r))
		if strings.IndexFunc(lower, func(c rune) bool { return c < utf8.RuneSelf }) < 0 {
			continue
		}
		found++
		if !mayBePHPPhishing([]byte(string(r))) {
			t.Errorf("U+%04X lowers to %q but the prefilter drops it", r, lower)
		}
	}
	if found == 0 {
		t.Fatal("no rune lowers to ASCII; the scan above is not exercising strings.ToLower")
	}
}

func TestPHPPhishingPrefilterKeepsDetections(t *testing.T) {
	for name, content := range map[string]string{
		"dropbox kit":            dropboxPhishPHP,
		"upper-case dropbox kit": strings.ToUpper(dropboxPhishPHP),
		"dotted capital I kit":   dottedCapitalIPHPKit,
	} {
		t.Run(name, func(t *testing.T) {
			if analyzePHPPhishingContent(content) == nil {
				t.Fatal("sample is not a detection; it cannot pin the prefilter")
			}
			if !mayBePHPPhishing([]byte(content)) {
				t.Fatal("prefilter drops a detected kit")
			}
			path := filepath.Join(t.TempDir(), "kit.php")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if analyzePHPForPhishing(context.Background(), path) == nil {
				t.Fatal("file scan lost a detected kit")
			}
		})
	}
}

// A credential pattern the prefilter cannot see would be dropped before it is
// ever searched for.
func TestPHPPhishingPrefilterKeepsCredentialPatterns(t *testing.T) {
	for _, pattern := range phpPhishingPatterns {
		if !mayBePHPPhishing([]byte(pattern)) {
			t.Errorf("prefilter drops credential pattern %q", pattern)
		}
	}
}
