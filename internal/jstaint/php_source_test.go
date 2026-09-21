package jstaint

import (
	"context"
	"testing"
)

// The deep walk hands every readable file to this analyzer and relies on the
// pre-filter to reject the rest. The filter needs a key-handler token plus one
// of a very common set (`src` matches almost any markup), so stock PHP passes
// it, fails to parse as JavaScript, and is then reported as JavaScript the
// scan could not examine. PHP source is not JavaScript, so it is not a
// candidate - reporting it as a parse failure invents a coverage gap that no
// operator action can close.
func TestPHPSourceIsNotAJavaScriptCandidate(t *testing.T) {
	php := []byte("<?php\n// wp-admin/includes/image-edit.php\n" +
		"$src = wp_get_attachment_url( $id );\n" +
		"?>\n<script>jQuery(document).on('keydown', function(){});</script>\n")

	got := Analyze(context.Background(), php)
	if got.Status == StatusParseError {
		t.Fatalf("PHP source reported as a JavaScript parse failure: %s", got.Reason)
	}
	if got.Status != StatusNotCandidate {
		t.Fatalf("PHP source status = %v, want %v", got.Status, StatusNotCandidate)
	}
}

// A short opening tag counts too, and a file that only reaches PHP after some
// leading whitespace is still PHP.
func TestPHPShortOpenTagIsNotACandidate(t *testing.T) {
	for name, src := range map[string]string{
		"short echo":         "<?= $x ?>\n<script>onkeydown=function(){fetch('/')}</script>",
		"leading whitespace": "\n\n  <?php $src = 1; ?>\n<script>onkeyup=()=>fetch('/')</script>",
	} {
		if got := Analyze(context.Background(), []byte(src)); got.Status != StatusNotCandidate {
			t.Errorf("%s: status = %v, want not_candidate", name, got.Status)
		}
	}
}

// Real JavaScript that happens to mention the tag inside a string literal is
// still analyzed: the marker only counts where PHP would actually open.
func TestJavaScriptMentioningPHPTagIsStillAnalyzed(t *testing.T) {
	src := []byte("const t = '<?php echo 1; ?>';\ndocument.addEventListener('keydown', e => fetch('/x?k=' + e.key));\n")
	if got := Analyze(context.Background(), src); got.Status != StatusAnalyzed {
		t.Fatalf("JavaScript containing a PHP tag in a string was not analyzed: status=%v reason=%s", got.Status, got.Reason)
	}
}

func TestNonJavaScriptDocumentsAreNotCandidates(t *testing.T) {
	for name, src := range map[string]string{
		"html before php": `<html><body><?php $src = 1; ?><script>onkeydown=()=>fetch('/')</script></body></html>`,
		"html":            `<!doctype html><script>onkeydown=()=>fetch('/')</script>`,
		"html comment":    "<!-- template -->\n<html><?php $src = 1; ?>onkeydown</html>",
		"bom php":         "\xef\xbb\xbf \n<?PHP $src = 'keydown'; ?>",
		"json":            `{"keydown": "send"}`,
		"source map":      `{"version":3,"sources":["input.js"],"sourcesContent":["document.onkeydown=e=>fetch(e.key)"],"mappings":"AAAA"}`,
		"css":             `.onkeydown { background: url('/src/image.png'); }`,
		"css import":      `@import url("/keydown-src.css");`,
		"css empty rule":  `.onkeydown[src] {}`,
		"css selectors":   `input[src="keydown"]:not(.open) { color: red; }`,
		"css media":       `@media screen { .onkeyup { content: "send"; } }`,
		"catalog plural":  "msgctxt\t\"keydown src\"\nmsgid \"key\"\nmsgid_plural \"keys\"\nmsgstr[0] \"send\"\n\" more\"\nmsgstr[1] \"send more\"\n",
		"translations":    "# catalog\nmsgid \"keydown\"\nmsgstr \"send\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if !isCandidate([]byte(src)) {
				t.Fatal("fixture must pass the token filter")
			}
			if got := Analyze(context.Background(), []byte(src)); got.Status != StatusNotCandidate {
				t.Fatalf("status=%v reason=%s, want not_candidate", got.Status, got.Reason)
			}
		})
	}
}

func TestDocumentMarkersDoNotHideJavaScript(t *testing.T) {
	for name, prefix := range map[string]string{
		"line comment":    "// <?php\n",
		"block comment":   "/* <?php */\n",
		"string":          "'<?php';\n",
		"template":        "`<html><?php`;\n",
		"html string":     "'<html>';\n",
		"html comment":    "<!-- <?php\n",
		"css comment":     "/* .onkeydown { content: 'send'; } */\n",
		"json expression": `({"keydown":"send"});`,
		"json array":      `["keydown", "send"];`,
	} {
		t.Run(name, func(t *testing.T) {
			src := prefix + `document.addEventListener('keydown', e => fetch('/x?k=' + e.key));`
			got := Analyze(context.Background(), []byte(src))
			if got.Status != StatusAnalyzed || got.TotalResults != 1 {
				t.Fatalf("report=%+v, want analyzed with one flow", got)
			}
		})
	}
}

func TestAmbiguousDocumentsKeepParseFailures(t *testing.T) {
	for name, src := range map[string]string{
		"broken js mentioning php":       `const t = '<?php'; document.onkeydown=e=>fetch(e.key`,
		"broken js after comment":        "/* <?php */\ndocument.onkeydown=e=>fetch(e.key",
		"truncated json with code":       `{"keydown":"send"}; document.onkeydown=e=>fetch(e.key`,
		"broken function resembling css": `function onkeydown() { src: "send"; const }`,
		"broken js resembling css":       `document.onkeydown = => { src: "keydown"; }`,
		"broken css block":               `.onkeydown { content: "send";`,
		"broken css":                     `.onkeydown { content: "send`,
		"translations with code":         "msgid \"keydown\"\nmsgstr \"send\"\ndocument.onkeydown=e=>fetch(e.key)",
		"not a php tag":                  `<?phpx keydown src`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := Analyze(context.Background(), []byte(src)); got.Status != StatusParseError {
				t.Fatalf("report=%+v, want parse_error", got)
			}
		})
	}
}
