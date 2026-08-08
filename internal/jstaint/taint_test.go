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

func TestScalar_FetchInitUsesPropertyEvaluationState(t *testing.T) {
	t.Run("later clean write does not erase body value", func(t *testing.T) {
		src := `document.onkeydown=function(e){var x=e.key;fetch("/c",{body:x,after:(x="")});};`
		got := analyzeSrc(t, src)
		if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchBody {
			t.Fatalf("Results = %+v, want one fetch body flow", got.Results)
		}
	})

	t.Run("later taint does not contaminate body value", func(t *testing.T) {
		src := `document.onkeydown=function(e){var x="";fetch("/c",{body:x,after:(x=e.key)});};`
		mustNotDetect(t, src)
	})

	t.Run("body is not evaluated twice", func(t *testing.T) {
		src := `document.onkeydown=function(e){var x=e.key;` +
			`fetch("/c",{body:(x=""),after:(x=e.key)});fetch("/next?"+x);};`
		got := analyzeSrc(t, src)
		if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
			t.Fatalf("Results = %+v, want one later fetch URL flow", got.Results)
		}
	})
}

func TestScalar_FetchInitUsesFinalDuplicateProperty(t *testing.T) {
	mustNotDetect(t, `document.onkeydown=function(e){fetch("/c",{body:e.key,body:""});};`)

	got := analyzeSrc(t, `document.onkeydown=function(e){fetch("/c",{body:"",body:e.key});};`)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchBody {
		t.Fatalf("Results = %+v, want one fetch body flow", got.Results)
	}
}

func TestScalar_FetchInitComputedPropertyUsesFinalValue(t *testing.T) {
	mustNotDetect(t, `document.onkeydown=function(e){fetch("/c",{["body"]:e.key,["body"]:""});};`)

	got := analyzeSrc(t, `document.onkeydown=function(e){fetch("/c",{["body"]:"",["body"]:e.key});};`)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchBody {
		t.Fatalf("Results = %+v, want one fetch body flow", got.Results)
	}
}

func TestScalar_FetchInitSpreadUsesFinalDefiniteProperty(t *testing.T) {
	mustNotDetect(t, `document.onkeydown=function(e){var clean={body:""};`+
		`fetch("/c",{body:e.key,...clean});};`)

	got := analyzeSrc(t, `document.onkeydown=function(e){var tainted={body:e.key};`+
		`fetch("/c",{body:"",...tainted});};`)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchBody {
		t.Fatalf("Results = %+v, want one fetch body flow", got.Results)
	}
}

func TestScalar_FetchInitMaybeAbsentSpreadDoesNotClearBody(t *testing.T) {
	src := `document.onkeydown=function(e){var patch={};if(window.p){patch.body="";}` +
		`fetch("/c",{body:e.key,...patch});};`
	got := analyzeSrc(t, src)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchBody {
		t.Fatalf("Results = %+v, want one fetch body flow", got.Results)
	}
}

func TestScalar_FetchBodyAndReferrerRemainDistinctFlows(t *testing.T) {
	src := `document.onkeydown=function(e){fetch("/c",{body:e.key,referrer:e.key});};`
	got := analyzeSrc(t, src)
	if len(got.Results) != 2 {
		t.Fatalf("Results = %+v, want separate body and referrer flows", got.Results)
	}
	if got.Results[0].Sink != sinkFetchBody || got.Results[1].Sink != sinkFetchReferrer {
		t.Fatalf("Results = %+v, want body and referrer sinks", got.Results)
	}
}

func TestScalar_FetchInitAcceptsQuotedProperty(t *testing.T) {
	got := analyzeSrc(t, `document.onkeydown=function(e){fetch("/c",{"body":e.key});};`)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchBody {
		t.Fatalf("Results = %+v, want one fetch body flow", got.Results)
	}
}

func TestScalar_ObjectComputedPropertySideEffectsAreAnalyzed(t *testing.T) {
	got := analyzeSrc(t, `document.onkeydown=function(e){({[fetch(e.key)]:0});};`)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_DestructuringBindingSideEffectsAreAnalyzed(t *testing.T) {
	for _, body := range []string{
		`const {[fetch(e.key)]:value}=window.obj;`,
		`for(const {[fetch(e.key)]:value} of window.items){}`,
	} {
		t.Run(body, func(t *testing.T) {
			got := analyzeSrc(t, `document.onkeydown=function(e){`+body+`};`)
			if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
				t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
			}
		})
	}
}

func TestScalar_ConditionalExpressionMergesBranchWrites(t *testing.T) {
	src := `document.onkeydown=function(e){var x="";window.p?(x=e.key):(x="");fetch(x);};`
	got := analyzeSrc(t, src)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_LogicalExpressionPreservesSkippedRHSState(t *testing.T) {
	src := `document.onkeydown=function(e){var x=e.key;window.p&&(x="");fetch(x);};`
	got := analyzeSrc(t, src)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_LogicalAssignmentPreservesSkippedRHSState(t *testing.T) {
	src := `document.onkeydown=function(e){var x="";var y=e.key;x&&=(y="");fetch(y);};`
	got := analyzeSrc(t, src)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_CompoundAssignmentReadsOldValueBeforeRHS(t *testing.T) {
	src := `document.onkeydown=function(e){var x=e.key;x+=(x="");fetch(x);};`
	got := analyzeSrc(t, src)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_CallEvaluatesReceiverBeforeArguments(t *testing.T) {
	src := `document.onkeydown=function(e){var x="";(x=e.key).concat(x="");fetch(x);};`
	mustNotDetect(t, src)
}

func TestScalar_OptionalChainPreservesSkippedArgumentState(t *testing.T) {
	src := `document.onkeydown=function(e){var x=e.key;var o=null;o?.m(x="");fetch(x);};`
	got := analyzeSrc(t, src)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_OptionalChainPreservesSkippedComputedMemberState(t *testing.T) {
	for _, expr := range []string{
		`o?.m[x=""]`,
		`o?.m[x=""]()`,
	} {
		t.Run(expr, func(t *testing.T) {
			src := `document.onkeydown=function(e){var x=e.key;var o=null;` + expr + `;fetch(x);};`
			got := analyzeSrc(t, src)
			if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
				t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
			}
		})
	}
}

func TestScalar_NestedCallInCalleePositionIsAnalyzed(t *testing.T) {
	got := analyzeSrc(t, `document.onkeydown=function(e){fetch(e.key)();};`)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_UnknownTaggedTemplateReturnIsClean(t *testing.T) {
	mustNotDetect(t, `document.onkeydown=function(e){var x=tag`+"`"+`${e.key}`+"`"+`;fetch(x);};`)

	got := analyzeSrc(t, `document.onkeydown=function(e){tag`+"`"+`${fetch(e.key)}`+"`"+`;};`)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want the nested fetch URL flow", got.Results)
	}
}

func TestScalar_BuiltinsIgnoreUnusedArguments(t *testing.T) {
	for _, expr := range []string{
		`String("safe",e.key)`,
		`encodeURIComponent("safe",e.key)`,
		`"safe".charAt(e.which)`,
		`"safe".slice(e.which)`,
		`"safe".substr(e.which)`,
		`"safe".substring(e.which)`,
		`"safe".trim(e.key)`,
		`"safe".toString(e.key)`,
	} {
		t.Run(expr, func(t *testing.T) {
			mustNotDetect(t, `document.onkeydown=function(e){fetch(`+expr+`);};`)
		})
	}
}

func TestScalar_ArrayAndObjectMethodsDoNotCreateScalarTaint(t *testing.T) {
	for _, expr := range []string{
		`[].concat(e.key)`,
		`({concat:function(x){return x;}}).concat(e.key)`,
		`(/x/).concat(e.key)`,
		`null?.concat(e.key)`,
	} {
		t.Run(expr, func(t *testing.T) {
			mustNotDetect(t, `document.onkeydown=function(e){fetch(`+expr+`);};`)
		})
	}
}

func TestScalar_StaticBracketNetworkSinks(t *testing.T) {
	for _, src := range []string{
		`document.onkeydown=function(e){window["fetch"](e.key);};`,
		`document.onkeydown=function(e){window["navigator"]["sendBeacon"]("/c",e.key);};`,
	} {
		t.Run(src, func(t *testing.T) {
			if got := analyzeSrc(t, src); len(got.Results) != 1 {
				t.Fatalf("Results = %+v, want one network flow", got.Results)
			}
		})
	}
}

func TestScalar_DoWhileAppliesFirstIterationStrongUpdate(t *testing.T) {
	src := `document.onkeydown=function(e){var x=e.key;do{x="";}while(window.p);fetch(x);};`
	mustNotDetect(t, src)
}

func TestScalar_ForOfBindsScalarElementBeforeBody(t *testing.T) {
	got := analyzeSrc(t, `document.onkeydown=function(e){for(const ch of e.key){fetch(ch);}};`)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_ForInAndForOfStrongUpdateIterationVariable(t *testing.T) {
	for _, loop := range []string{
		`for(x in window.obj){fetch(x);}`,
		`for(x of "ab"){fetch(x);}`,
	} {
		t.Run(loop, func(t *testing.T) {
			mustNotDetect(t, `document.onkeydown=function(e){var x=e.key;`+loop+`};`)
		})
	}
}

func TestScalar_ForOfPreservesZeroIterationPath(t *testing.T) {
	src := `document.onkeydown=function(e){var x=e.key;for(x of []){}fetch(x);};`
	got := analyzeSrc(t, src)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_LaterParameterDefaultRunsBeforeHandlerBody(t *testing.T) {
	src := `document.onkeydown=function(e,payload=e.key){fetch(payload);};`
	got := analyzeSrc(t, src)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_VarRedeclarationDoesNotClearValue(t *testing.T) {
	src := `document.onkeydown=function(e){var x=e.key;var x;fetch(x);};`
	got := analyzeSrc(t, src)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_WithStatementBodyIsAnalyzed(t *testing.T) {
	got := analyzeSrc(t, `document.onkeydown=function(e){with(window){fetch(e.key);}};`)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_WithStatementDoesNotStrongUpdateOuterBinding(t *testing.T) {
	src := `document.onkeydown=function(e){var x=e.key;with(window.p){x="";}fetch(x);};`
	got := analyzeSrc(t, src)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_ClassDefinitionSideEffectsAreAnalyzed(t *testing.T) {
	for _, body := range []string{
		`class X{static{fetch(e.key);}}`,
		`class X{[fetch(e.key)](){}}`,
		`class X{static value=fetch(e.key);}`,
	} {
		t.Run(body, func(t *testing.T) {
			got := analyzeSrc(t, `document.onkeydown=function(e){`+body+`};`)
			if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
				t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
			}
		})
	}
}

func TestScalar_ClassStaticBlockPublishesMergedState(t *testing.T) {
	src := `document.onkeydown=function(e){var x="";class X{static{if(window.p){x=e.key;}}}fetch(x);};`
	got := analyzeSrc(t, src)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_ClassComputedNamesRunBeforeStaticInitializers(t *testing.T) {
	src := `document.onkeydown=function(e){var x=e.key;` +
		`class X{static value=(x="");[fetch(x)](){}}};`
	got := analyzeSrc(t, src)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_ComputedClassNameHandlerIsAnalyzed(t *testing.T) {
	src := `class X{[document.onkeydown=function(e){fetch(e.key);} ](){}}`
	got := analyzeSrc(t, src)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_ComputedClassNameHonorsRecursionLimit(t *testing.T) {
	expr := strings.Repeat("!", maxAnalysisDepth+1) + `fetch(e.key)`
	src := `document.onkeydown=function(e){class X{[` + expr + `](){}}};`
	got := Analyze(context.Background(), []byte(src))
	if got.Status != StatusResourceLimit {
		t.Fatalf("Status = %v (%s), want StatusResourceLimit", got.Status, got.Reason)
	}
}

func TestScalar_AwaitPropagatesValue(t *testing.T) {
	src := `document.onkeydown=async function(e){fetch(await e.key);};`
	got := analyzeSrc(t, src)
	if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
		t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
	}
}

func TestScalar_GlobalObjectBuiltinFormsPropagate(t *testing.T) {
	for _, expr := range []string{
		`window["String"](e.key)`,
		`self.String["fromCharCode"](e.which)`,
		`globalThis["JSON"].stringify(e.key)`,
	} {
		t.Run(expr, func(t *testing.T) {
			got := analyzeSrc(t, `document.onkeydown=function(e){fetch(`+expr+`);};`)
			if len(got.Results) != 1 || got.Results[0].Sink != sinkFetchURL {
				t.Fatalf("Results = %+v, want one fetch URL flow", got.Results)
			}
		})
	}
}

func TestScalar_ResultInsertionHonorsFactLimit(t *testing.T) {
	a := analysis{
		ctx:     context.Background(),
		budget:  &resourceBudget{facts: maxPropagatedFacts},
		display: map[int]string{0: "e.key"},
		results: map[flowKey]Result{},
	}
	a.record(taintSet{0: nil}, nil, 0, sinkFetchURL)
	if a.err != errFactLimit {
		t.Fatalf("error = %v, want %v", a.err, errFactLimit)
	}
	if len(a.results) != 0 {
		t.Fatalf("recorded %d result after reaching the fact limit", len(a.results))
	}
}
