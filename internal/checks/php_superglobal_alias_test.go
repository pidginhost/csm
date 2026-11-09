package checks

import (
	"strings"
	"testing"
)

// ${'_POST'} and $GLOBALS['_POST'] are PHP's other spellings of $_POST.
// Vendor code uses them to get past marketplace validators, and a shell can
// use them to get past ours, so request input must grade the same either way.
func TestRequestInputAliasesGradeLikeSuperglobal(t *testing.T) {
	shapes := []string{
		"eval(SG['c']);",
		"system(SG['c']);",
		"assert(SG['x']);",
		"include SG['p'];",
		"preg_replace('/x/e', SG['r'], 'x');",
	}
	aliases := []string{
		`${'_POST'}`,
		`${"_POST"}`,
		`${ '_POST' }`,
		"${/* x */'_POST'}",
		`$GLOBALS['_POST']`,
		`$GLOBALS [ "_POST" ]`,
	}
	grade := func(src string) phpAnalysisResult {
		return analyzePHPCode("/home/u/public_html/x.php", phpCodeOnly(src), true)
	}
	for _, shape := range shapes {
		want := grade("<?php\n" + strings.ReplaceAll(shape, "SG", "$_POST") + "\n")
		if want.severity < 0 {
			t.Fatalf("%s: plain $_POST not graded; the shape no longer tests anything", shape)
		}
		for _, alias := range aliases {
			src := "<?php\n" + strings.ReplaceAll(shape, "SG", alias) + "\n"
			if got := grade(src); got.severity != want.severity {
				t.Errorf("%q: severity %d %v, want %d %v", src, got.severity, got.indicators, want.severity, want.indicators)
			}
		}
	}
}

// Detectors report offsets and line numbers, so the rewrite must not move
// any byte of the code around it.
func TestSuperglobalAliasRewriteKeepsLayout(t *testing.T) {
	src := "<?php\n$a = ${\n'_GET'\n}['x'];\n$b = $GLOBALS['_COOKIE']['y']; echo 'ok';\n"
	code := phpCodeOnly(src)
	if len(code) != len(src) || strings.Count(code, "\n") != strings.Count(src, "\n") {
		t.Fatalf("layout moved: %q", code)
	}
	for _, want := range []string{"$_GET", "$_COOKIE['y']", "echo 'ok';"} {
		if !strings.Contains(code, want) {
			t.Errorf("code %q lacks %q", code, want)
		}
	}
}
