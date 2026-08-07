package jstaint

import (
	"context"
	"strings"
	"testing"
)

func analyzeSrc(t *testing.T, src string) Report {
	t.Helper()
	got := Analyze(context.Background(), []byte(src))
	if got.Status != StatusAnalyzed {
		t.Fatalf("Status = %v (%s), want StatusAnalyzed", got.Status, got.Reason)
	}
	return got
}

func firstResult(t *testing.T, src string) Result {
	t.Helper()
	got := analyzeSrc(t, src)
	if len(got.Results) == 0 {
		t.Fatalf("no flow detected, want one")
	}
	return got.Results[0]
}

func mustNotDetect(t *testing.T, src string) {
	t.Helper()
	got := analyzeSrc(t, src)
	if len(got.Results) != 0 {
		t.Fatalf("detected %d flow(s), want none: %+v", len(got.Results), got.Results)
	}
}

func TestScalar_DirectSourceToFetch(t *testing.T) {
	r := firstResult(t, `document.onkeydown=function(e){fetch("/c?k="+e.key);};`)
	if r.Source != "e.key" {
		t.Errorf("Source = %q, want e.key", r.Source)
	}
	if !strings.HasPrefix(r.Sink, "fetch") {
		t.Errorf("Sink = %q, want a fetch sink", r.Sink)
	}
}

func TestScalar_OneHopThroughVariable(t *testing.T) {
	r := firstResult(t, `document.onkeydown=function(e){var c=e.key;fetch("/c?k="+c);};`)
	if r.Source != "e.key" {
		t.Errorf("Source = %q, want e.key", r.Source)
	}
	if strings.Join(r.Via, ",") != "c" {
		t.Errorf("Via = %v, want [c]", r.Via)
	}
}

func TestScalar_TwoHopsThroughFromCharCode(t *testing.T) {
	src := `document.onkeypress=function(e){var code=e.which;var ch=String.fromCharCode(code);` +
		`var out="";out+=ch;fetch("/c?k="+out);};`
	r := firstResult(t, src)
	if r.Source != "e.which" {
		t.Errorf("Source = %q, want e.which", r.Source)
	}
	if strings.Join(r.Via, ",") != "code,ch,out" {
		t.Errorf("Via = %v, want [code ch out]", r.Via)
	}
}

func TestScalar_CompoundAccumulateToBeacon(t *testing.T) {
	src := `document.onkeypress=function(e){var b="";b+=e.key;navigator.sendBeacon("/c",b);};`
	r := firstResult(t, src)
	if r.Source != "e.key" || !strings.Contains(r.Sink, "sendBeacon") {
		t.Errorf("got Source=%q Sink=%q, want e.key -> sendBeacon", r.Source, r.Sink)
	}
}

func TestScalar_FetchBodyOption(t *testing.T) {
	src := `document.onkeydown=function(e){fetch("/c",{method:"POST",body:e.key});};`
	r := firstResult(t, src)
	if !strings.Contains(r.Sink, "body") {
		t.Errorf("Sink = %q, want the fetch body option", r.Sink)
	}
}

func TestScalar_SendBeaconURLTainted(t *testing.T) {
	src := `document.onkeydown=function(e){navigator.sendBeacon("/c?k="+e.key,"d");};`
	r := firstResult(t, src)
	if !strings.Contains(r.Sink, "url") {
		t.Errorf("Sink = %q, want the sendBeacon url argument", r.Sink)
	}
}

func TestScalar_BranchMergePositive(t *testing.T) {
	// One branch taints c; the merged state at the sink is still tainted.
	src := `document.onkeydown=function(e){var c="";if(window.x){c=e.key;}fetch("/c?k="+c);};`
	firstResult(t, src)
}

func TestScalar_LoopAccumulate(t *testing.T) {
	src := `document.onkeydown=function(e){var b="";for(var i=0;i<3;i++){b+=e.key;}fetch("/c",{body:b});};`
	firstResult(t, src)
}

func TestScalar_TryFinallyEdge(t *testing.T) {
	src := `document.onkeydown=function(e){var c="";try{c=e.key;}finally{fetch("/c?k="+c);}};`
	firstResult(t, src)
}

func TestScalar_CleanOverwriteKillsTaint(t *testing.T) {
	// c is overwritten with a constant before the sink on every path.
	mustNotDetect(t, `document.onkeydown=function(e){var c=e.key;c="const";fetch("/c?k="+c);};`)
}

func TestScalar_ComparisonBarrierIsNotSent(t *testing.T) {
	// The boolean result of a comparison does not carry the key value.
	mustNotDetect(t, `document.onkeydown=function(e){var c=(e.which===13);fetch("/c?k="+c);};`)
}

func TestScalar_TargetValueIsNotASource(t *testing.T) {
	mustNotDetect(t, `document.onkeydown=function(e){fetch("/c?k="+e.target.value);};`)
}

func TestScalar_SourceReadButNeverSent(t *testing.T) {
	mustNotDetect(t, `document.onkeydown=function(e){var c=e.key;console.log(c);};fetch("/c");`)
}

func TestScalar_ShadowedFetchIsNotASink(t *testing.T) {
	// A local function named fetch is not the browser global.
	src := `document.onkeydown=function(e){function fetch(u){return u;}fetch("/c?k="+e.key);};`
	mustNotDetect(t, src)
}
