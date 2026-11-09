package checks

import (
	"fmt"
	"reflect"
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

func TestSuperglobalAliasesDoNotTurnDataIntoInput(t *testing.T) {
	for _, data := range []string{
		`'${"_POST"}'`,
		`'$GLOBALS["_POST"]'`,
		`"\${'_POST'}"`,
		"<<<'TEXT'\n${'_POST'}\nTEXT",
		"<<<TEXT\n\\${'_POST'}\nTEXT",
		`${/* first */ '_SAFE' . /* second */ '_POST'}`,
		`"{$items['${\"_POST\"}']}"`,
	} {
		t.Run(data, func(t *testing.T) {
			src := "<?php $data = " + data + "; system('true');"
			if got := analyzePHPCode("/home/u/public_html/data.php", phpCodeOnly(src), true); got.severity >= 0 {
				t.Errorf("data produced request-input findings: %v", got.indicators)
			}
			if got := canonicalSuperglobalAliases(src); got != src {
				t.Errorf("literal data changed: %q", got)
			}
		})
	}
}

func TestSuperglobalAliasesPreserveLineBreakOffsets(t *testing.T) {
	src := "<?php\r\n$x = ${\r\n'_POST'\r\n}['x'];\r\neval($GLOBALS[/*\r\n*/'_GET']);"
	code := phpCodeOnly(src)
	if len(code) != len(src) {
		t.Fatalf("length = %d, want %d", len(code), len(src))
	}
	for i := range src {
		if (src[i] == '\r' || src[i] == '\n') && src[i] != code[i] {
			t.Errorf("line break at byte %d changed", i)
		}
	}
	if strings.Index(src, "eval(") != strings.Index(code, "eval(") {
		t.Error("following call moved")
	}
}

func TestSuperglobalAliasesAfterHeredocAndInInterpolation(t *testing.T) {
	for _, expression := range []string{
		`${'_POST'}['x']`,
		`"{${'_POST'}['x']}"`,
		`"{$GLOBALS['_POST']['x']}"`,
		`"{${'_POST'}["x"]}"`,
		`"{$GLOBALS['_POST']["x"]}"`,
		"<<<TEXT\n{${'_POST'}['x']}\nTEXT",
	} {
		src := "<?php $text = <<<'TEXT'\n${'_GET'}\nTEXT;\ninclude " + expression + ";"
		got := analyzePHPCode("/home/u/public_html/input.php", phpCodeOnly(src), true)
		want := []string{"include/require of request input or remote/data wrapper"}
		if !reflect.DeepEqual(got.indicators, want) {
			t.Errorf("%s: indicators = %v, want %v", expression, got.indicators, want)
		}
	}
}

func TestSuperglobalAliasTriviaDoesNotHideInput(t *testing.T) {
	for _, alias := range []string{
		"${# name\r'_POST'// end\r}",
		"$GLOBALS[/* first */'_POST'/* last */]",
		"${\v'_POST'\f}",
	} {
		code := phpCodeOnly("<?php eval(" + alias + "['c']);")
		got := analyzePHPCode("/home/u/public_html/input.php", code, true)
		if !reflect.DeepEqual(got.indicators, []string{"eval() of request input"}) {
			t.Errorf("%q: lost request input: %v", alias, got.indicators)
		}
	}
}

func TestStripPHPBlocksDoesNotExposeAliasPadding(t *testing.T) {
	src := "<?php $x = ${/* hidden marker */'_POST'}['x']; ?>visible"
	got := stripPHPBlocks(src)
	if strings.Contains(got, "hidden") || !strings.HasSuffix(got, "visible") || len(got) != len(src) {
		t.Fatalf("PHP code exposed as visible text: %q", got)
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

func BenchmarkCanonicalSuperglobalAliases(b *testing.B) {
	for name, chunk := range map[string]string{
		"aliases":     `${'_POST'}['x']; `,
		"near_misses": `${/* x */ '_SAFE' . /* x */ '_POST'}; `,
		"literals":    `'$GLOBALS["_POST"]'; `,
	} {
		for _, size := range []int{1 << 20, 4 << 20} {
			b.Run(fmt.Sprintf("%s/%dMiB", name, size>>20), func(b *testing.B) {
				code := strings.Repeat(chunk, size/len(chunk))
				b.SetBytes(int64(len(code)))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					canonicalSuperglobalAliases(code)
				}
			})
		}
	}
}
