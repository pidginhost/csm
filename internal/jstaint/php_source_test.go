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
		if got := Analyze(context.Background(), []byte(src)); got.Status == StatusParseError {
			t.Errorf("%s: PHP source reported as a JavaScript parse failure", name)
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
