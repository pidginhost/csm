package checks

import (
	"strings"
	"testing"
)

// PHP ends a "//" or "#" comment at "?>" as well as at a newline, so code
// after a closing tag on the same line runs. Comment stripping must leave it
// visible, or a payload hides behind a one-line comment.

func TestAnalyzePHPCodeLineCommentClosedByTagStillScansCode(t *testing.T) {
	for _, comment := range []string{"//", "#"} {
		src := "<?php " + comment + " build note ?><?php eval(base64_decode('ZWNobyAxOw=='));\n"
		res := analyzePHPCode("/home/u/public_html/x.php", phpCodeOnly(src), true)
		if len(res.indicators) == 0 {
			t.Errorf("%s: eval(base64_decode()) after a tag-closed line comment produced no indicator", comment)
		}
	}
}

func TestStripPHPCommentsFromCodeEndsLineCommentAtCloseTag(t *testing.T) {
	for _, comment := range []string{"//", "#"} {
		src := "<?php " + comment + " note ?><?php eval($x);"
		got := stripPHPCommentsFromCode(src)
		if !strings.Contains(got, "?><?php eval($x);") {
			t.Errorf("%s: code after the closing tag was blanked: %q", comment, got)
		}
		if strings.Contains(got, "note") {
			t.Errorf("%s: comment text survived: %q", comment, got)
		}
		if len(got) != len(src) {
			t.Errorf("%s: length changed from %d to %d", comment, len(src), len(got))
		}
	}
}
