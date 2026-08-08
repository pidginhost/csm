package jstaint

import "testing"

// Depth-1 interprocedural: a captured key passed into a same-file helper that
// sinks, or returned tainted from a helper, is detected; a two-user-function
// chain is not, because a depth-1 fact cannot enter a second callee.

func TestInterproc_HelperThatSinksIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){ship(e.key);};function ship(v){fetch("/c?k="+v);}`
	firstResult(t, src)
}

func TestInterproc_HelperReturningTaintedValueIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var x=enc(e.key);fetch("/c?k="+x);};function enc(v){return btoa(v);}`
	firstResult(t, src)
}

func TestInterproc_HelperReturningTaintedObjectFieldIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var o=wrap(e.key);navigator.sendBeacon("/c",JSON.stringify(o));};` +
		`function wrap(v){var r={};r.k=v;return r;}`
	firstResult(t, src)
}

func TestInterproc_DepthTwoChainNotDetected(t *testing.T) {
	// first(key) -> second(key) where only second sinks. The depth-1 boundary
	// stops the key entering the second callee, so nothing is reported.
	src := `document.onkeydown=function(e){first(e.key);};` +
		`function first(k){second(k);}function second(k){fetch("/c?k="+k);}`
	mustNotDetect(t, src)
}

func TestInterproc_HelperNotSharingKeyIsNotDetected(t *testing.T) {
	// The helper sinks a constant, not the passed key.
	src := `document.onkeydown=function(e){ship(e.key);};function ship(v){fetch("/c?k=const");}`
	mustNotDetect(t, src)
}

// Cross-callback file-scope may-state: one callback taints a shared buffer, a
// separate reachable callback ships it.

func TestInterproc_BufferedSenderAcrossCallbacks(t *testing.T) {
	src := `var buf="";document.addEventListener("keydown",function(e){buf+=e.key;});` +
		`setInterval(function(){navigator.sendBeacon("/c",buf);},1000);`
	firstResult(t, src)
}

func TestInterproc_SetTimeoutSenderReadsTaintedGlobal(t *testing.T) {
	src := `var buf="";document.onkeydown=function(e){buf=e.key;};` +
		`setTimeout(function(){fetch("/c?k="+buf);},0);`
	firstResult(t, src)
}

func TestInterproc_GlobalObjectTimerCallbackIsReachable(t *testing.T) {
	src := `var buf="";document.onkeydown=function(e){buf=e.key;};` +
		`window["setTimeout"](function(){fetch("/c?k="+buf);},0);`
	firstResult(t, src)
}

func TestInterproc_ShadowedGlobalObjectTimerIsUnreachable(t *testing.T) {
	src := `var buf="";document.onkeydown=function(e){buf=e.key;};` +
		`function install(window){window.setTimeout(function(){fetch("/c?k="+buf);},0);}` +
		`install({});`
	mustNotDetect(t, src)
}

// Reachability: an unreferenced function that sinks a tainted global is not
// analyzed, and a top-level request that runs before any keystroke is clean.

func TestInterproc_UnreachableFunctionSinkNotDetected(t *testing.T) {
	// leak is never called or registered, so its sink is unreachable even though
	// the handler taints the shared buffer it would read.
	src := `var buf="";document.onkeydown=function(e){buf=e.key;};function leak(){fetch("/c?k="+buf);}`
	mustNotDetect(t, src)
}

func TestInterproc_TopLevelRequestBeforeHandlerNotDetected(t *testing.T) {
	// The top level runs once with a clean published state; it cannot consume a
	// taint a keyboard handler can only produce later.
	src := `var buf="";fetch("/c?k="+buf);document.onkeydown=function(e){buf=e.key;};`
	mustNotDetect(t, src)
}

func TestInterproc_HandlerRegisteredByCalledInitIsReachable(t *testing.T) {
	// A registration inside a function that the top level calls is reachable.
	src := `function init(){document.onkeydown=function(e){fetch("/c?k="+e.key);};}init();`
	firstResult(t, src)
}

func TestInterproc_RecursiveHelperTerminates(t *testing.T) {
	// Direct recursion must terminate under the callee re-entry guard.
	src := `document.onkeydown=function(e){r(e.key,0);};` +
		`function r(k,n){if(n>3){fetch("/c?k="+k);return;}r(k,n+1);}`
	analyzeSrc(t, src) // must not hang or panic; detection is not asserted here
}

func TestInterproc_ReturnedFactCannotEnterSecondCallee(t *testing.T) {
	src := `document.onkeydown=function(e){var k=first(e.key);second(k);};` +
		`function first(k){return k;}function second(k){fetch("/c?k="+k);}`
	mustNotDetect(t, src)
}

func TestInterproc_ReturnedObjectFactCannotEnterSecondCallee(t *testing.T) {
	src := `document.onkeydown=function(e){var value=wrap(e.key);ship(value);};` +
		`function wrap(k){return {key:k};}` +
		`function ship(value){fetch("/c",{body:JSON.stringify(value)});}`
	mustNotDetect(t, src)
}

func TestInterproc_ReturnedArgumentObjectReachesCallerSink(t *testing.T) {
	src := `document.onkeydown=function(e){var value={key:e.key};` +
		`var returned=identity(value);fetch("/c",{body:JSON.stringify(returned)});};` +
		`function identity(value){return value;}`
	firstResult(t, src)
}

func TestInterproc_NewFactOnReturnedObjectCanEnterCallee(t *testing.T) {
	src := `document.onkeydown=function(e){var value=make();value.key=e.key;ship(value);};` +
		`function make(){return {};}` +
		`function ship(value){fetch("/c",{body:JSON.stringify(value)});}`
	firstResult(t, src)
}

func TestInterproc_ObjectMutationFactCannotEnterSecondCallee(t *testing.T) {
	src := `document.onkeydown=function(e){var value={};put(value,e.key);ship(value);};` +
		`function put(value,k){value.key=k;}` +
		`function ship(value){fetch("/c",{body:JSON.stringify(value)});}`
	mustNotDetect(t, src)
}

func TestInterproc_DepthTwoReturnedObjectStaysBlockedAtCallerSink(t *testing.T) {
	src := `document.onkeydown=function(e){var value={};put(value,e.key);` +
		`var returned=identity(value);fetch("/c",{body:JSON.stringify(returned)});};` +
		`function put(value,k){value.key=k;}` +
		`function identity(value){return value;}`
	mustNotDetect(t, src)
}

func TestInterproc_CleanObjectWriteDoesNotResetDepthBarrier(t *testing.T) {
	src := `document.onkeydown=function(e){var value=wrap(e.key);ship(value);};` +
		`function wrap(k){return {key:k};}` +
		`function ship(value){value.clean={};fetch("/c",{body:JSON.stringify(value)});}`
	mustNotDetect(t, src)
}

func TestInterproc_DepthTwoObjectPublicationStaysBlocked(t *testing.T) {
	src := `var shared;document.onkeydown=function(e){` +
		`var value=identity({key:e.key});publish(value);};` +
		`setTimeout(function(){fetch("/c",{body:JSON.stringify(shared)});},0);` +
		`function identity(value){return value;}function publish(value){shared=value;}`
	mustNotDetect(t, src)
}

func TestInterproc_IndependentDepthOneCallsAreBothAnalyzed(t *testing.T) {
	src := `document.onkeydown=function(e){first(e.key);second(e.key);};` +
		`function first(k){fetch("/first?k="+k);}` +
		`function second(k){fetch("/second?k="+k);}`
	got := analyzeSrc(t, src)
	if len(got.Results) != 2 {
		t.Fatalf("Results = %+v, want two independent helper flows", got.Results)
	}
}

func TestInterproc_CalleeLocalsDoNotLeakAcrossCalls(t *testing.T) {
	src := `document.onkeydown=function(e){store(e.key);store("clean");};` +
		`function store(v){var local;fetch("/c?k="+local);local=v;}`
	mustNotDetect(t, src)
}

func TestInterproc_CalleeAlternativesStartFromSameCallerState(t *testing.T) {
	src := `document.onkeydown=function(e){var buf="";` +
		`var send=function(v){buf=v;};send=function(){fetch("/c?k="+buf);};send(e.key);};`
	mustNotDetect(t, src)
}

func TestInterproc_CalleeObjectMutationFlowsBack(t *testing.T) {
	src := `document.onkeydown=function(e){var state={};put(state,e.key);` +
		`navigator.sendBeacon("/c",JSON.stringify(state));};` +
		`function put(state,k){state.key=k;}`
	firstResult(t, src)
}

func TestInterproc_CalleeSharedWriteFlowsBack(t *testing.T) {
	src := `var buf="";document.onkeydown=function(e){store(e.key);};` +
		`setTimeout(function(){fetch("/c?k="+buf);},0);` +
		`function store(k){buf=k;}`
	firstResult(t, src)
}

func TestInterproc_CalleeCapturedLocalWriteFlowsBack(t *testing.T) {
	src := `document.onkeydown=function(e){var buf="";` +
		`function store(k){buf=k;}store(e.key);fetch("/c?k="+buf);};`
	firstResult(t, src)
}

func TestInterproc_DestructuredDefaultIsSkippedWhenArgumentExists(t *testing.T) {
	src := `document.onkeydown=function(e){` +
		`function helper({value}=ship(e.key)){}helper({value:"clean"});};` +
		`function ship(k){fetch("/c?k="+k);}`
	mustNotDetect(t, src)
}

func TestInterproc_NestedDestructuredDefaultSkipsPresentProperty(t *testing.T) {
	src := `document.onkeydown=function(e){` +
		`function helper({value=ship(e.key)}){}helper({value:"clean"});};` +
		`function ship(k){fetch("/c?k="+k);}`
	mustNotDetect(t, src)
}

func TestInterproc_ObjectDestructuredParameterBindsArgument(t *testing.T) {
	src := `document.onkeydown=function(e){ship({key:e.key});};` +
		`function ship({key}){fetch("/c?k="+key);}`
	firstResult(t, src)
}

func TestInterproc_ArrayDestructuredParameterBindsArgument(t *testing.T) {
	src := `document.onkeydown=function(e){ship([e.key]);};` +
		`function ship([key]){fetch("/c?k="+key);}`
	firstResult(t, src)
}

func TestInterproc_DestructuredParameterDefaultBindsValue(t *testing.T) {
	src := `document.onkeydown=function(e){` +
		`function ship({key}={key:e.key}){fetch("/c?k="+key);}ship();};`
	firstResult(t, src)
}

func TestInterproc_RestParameterBindsRemainingArguments(t *testing.T) {
	src := `document.onkeydown=function(e){ship("prefix",e.key);};` +
		`function ship(...parts){fetch("/c?k="+parts.join(""));}`
	firstResult(t, src)
}

func TestInterproc_ArrayRestParameterBindsRemainingElements(t *testing.T) {
	src := `document.onkeydown=function(e){ship(["prefix",e.key]);};` +
		`function ship([first,...parts]){fetch("/c?k="+parts.join(""));}`
	firstResult(t, src)
}

func TestInterproc_ObjectRestParameterBindsRemainingFields(t *testing.T) {
	src := `document.onkeydown=function(e){ship({clean:"ok",key:e.key});};` +
		`function ship({clean,...parts}){fetch("/c",{body:JSON.stringify(parts)});}`
	firstResult(t, src)
}

func TestInterproc_ObjectRestParameterExcludesNamedFields(t *testing.T) {
	src := `document.onkeydown=function(e){ship({key:e.key,clean:"ok"});};` +
		`function ship({key,...parts}){fetch("/c",{body:JSON.stringify(parts)});}`
	mustNotDetect(t, src)
}

func TestInterproc_DefaultRunsAtCalleeDepth(t *testing.T) {
	src := `document.onkeydown=function(e){` +
		`function first(value=second(e.key)){}first();};` +
		`function second(k){fetch("/c?k="+k);}`
	mustNotDetect(t, src)
}

func TestInterproc_AsyncHelperBodyIsAnalyzed(t *testing.T) {
	src := `document.onkeydown=function(e){ship(e.key);};` +
		`async function ship(k){fetch("/c?k="+k);}`
	firstResult(t, src)
}

func TestInterproc_AsyncHelperReturnIsNotCallerScalar(t *testing.T) {
	src := `document.onkeydown=function(e){var promise=wrap(e.key);fetch("/c?k="+promise);};` +
		`async function wrap(k){return k;}`
	mustNotDetect(t, src)
}

func TestInterproc_AwaitPublishesPreSuspensionSharedState(t *testing.T) {
	src := `var buf="";document.onkeydown=async function(e){` +
		`buf=e.key;await pause();buf="";};` +
		`setTimeout(function(){fetch("/c?k="+buf);},0);`
	firstResult(t, src)
}

func TestInterproc_UnreachableRegistrationDoesNotCreateSource(t *testing.T) {
	src := `function handler(e){fetch("/c?k="+e.key);}` +
		`function register(){document.onkeydown=handler;}` +
		`handler({key:"clean"});`
	mustNotDetect(t, src)
}

func TestInterproc_UncalledClassMethodRegistrationIsUnreachable(t *testing.T) {
	src := `var buf="";document.onkeydown=function(e){buf=e.key;};` +
		`class Hooks{install(){setTimeout(function(){fetch("/c?k="+buf);},0);}}`
	mustNotDetect(t, src)
}

func TestInterproc_StaticClassBlockRegistrationIsReachable(t *testing.T) {
	src := `class Hooks{static{document.onkeydown=function(e){fetch("/c?k="+e.key);};}}`
	firstResult(t, src)
}

func TestInterproc_KeyboardRegistrationUpgradesExistingTimerRoot(t *testing.T) {
	src := `function handler(e){fetch("/c?k="+e.key);}` +
		`setTimeout(handler,0);document.onkeydown=handler;`
	firstResult(t, src)
}

func TestInterproc_CalledGeneratorBodyIsUnreachable(t *testing.T) {
	src := `var buf="";document.onkeydown=function(e){buf=e.key;};` +
		`function* install(){setTimeout(function(){fetch("/c?k="+buf);},0);}install();`
	mustNotDetect(t, src)
}

func TestInterproc_RegistrationInCalledDefaultIsReachable(t *testing.T) {
	src := `function handler(e){fetch("/c?k="+e.key);}` +
		`function install(register=(document.onkeydown=handler)){}install();`
	firstResult(t, src)
}

func TestInterproc_SkippedCalledDefaultIsUnreachable(t *testing.T) {
	src := `function handler(e){fetch("/c?k="+e.key);}` +
		`function install(register=(document.onkeydown=handler)){}install("ready");`
	mustNotDetect(t, src)
}

func TestInterproc_SkippedTimerDefaultIsUnreachable(t *testing.T) {
	src := `function handler(e){fetch("/c?k="+e.key);}` +
		`function install(register=(document.onkeydown=handler)){}` +
		`setTimeout(install,0,"ready");`
	mustNotDetect(t, src)
}

func TestInterproc_ReturnStopsLaterCalleeEffects(t *testing.T) {
	src := `var buf="";document.onkeydown=function(e){store(e.key);};` +
		`setTimeout(function(){fetch("/c?k="+buf);},0);` +
		`function store(k){return;buf=k;}`
	mustNotDetect(t, src)
}

func TestInterproc_ReturnStopsLaterReturnValue(t *testing.T) {
	src := `document.onkeydown=function(e){fetch("/c?k="+clean(e.key));};` +
		`function clean(k){return "";return k;}`
	mustNotDetect(t, src)
}

func TestInterproc_AsyncContinuationDoesNotPrecedeCaller(t *testing.T) {
	src := `document.onkeydown=function(e){var buf="";store(e.key);fetch("/c?k="+buf);` +
		`async function store(k){await pause();buf=k;}};`
	mustNotDetect(t, src)
}

func TestInterproc_SynchronousCleanExitIsNotPublished(t *testing.T) {
	src := `var buf="";document.onkeydown=function(e){buf=e.key;buf="";};` +
		`setTimeout(function(){fetch("/c?k="+buf);},0);`
	mustNotDetect(t, src)
}

func TestInterproc_CalleeSharedObjectMutationPublishes(t *testing.T) {
	src := `var shared={};document.onkeydown=function(e){store(e.key);};` +
		`setTimeout(function(){fetch("/c",{body:JSON.stringify(shared)});},0);` +
		`function store(k){shared.key=k;}`
	firstResult(t, src)
}

func TestInterproc_ReturnStopsLaterCallbackSink(t *testing.T) {
	src := `var buf="";document.onkeydown=function(e){buf=e.key;};` +
		`setTimeout(function(){return;fetch("/c?k="+buf);},0);`
	mustNotDetect(t, src)
}

func TestInterproc_ReturningBranchKeepsFallthroughEffects(t *testing.T) {
	src := `var buf="";document.onkeydown=function(e){store(e.key);};` +
		`setTimeout(function(){fetch("/c?k="+buf);},0);` +
		`function store(k){if(window.stop){return;}buf=k;}`
	firstResult(t, src)
}

func TestInterproc_CallbackBranchExitPublishesMergedState(t *testing.T) {
	src := `var buf="";document.onkeydown=function(e){if(window.capture){buf=e.key;}};` +
		`setTimeout(function(){fetch("/c?k="+buf);},0);`
	firstResult(t, src)
}

func TestInterproc_FinallyAppliesToReturnedCalleeState(t *testing.T) {
	src := `var buf="";document.onkeydown=function(e){store(e.key);};` +
		`setTimeout(function(){fetch("/c?k="+buf);},0);` +
		`function store(k){try{return;}finally{buf=k;}}`
	firstResult(t, src)
}

func TestInterproc_FinallyReturnOverridesPendingValue(t *testing.T) {
	src := `document.onkeydown=function(e){fetch("/c?k="+clean(e.key));};` +
		`function clean(k){try{return k;}finally{return "";}}`
	mustNotDetect(t, src)
}

func TestInterproc_AsyncContinuationPublishesSharedState(t *testing.T) {
	src := `var buf="";document.onkeydown=function(e){store(e.key);};` +
		`setTimeout(function(){fetch("/c?k="+buf);},0);` +
		`async function store(k){await pause();buf=k;}`
	firstResult(t, src)
}

func TestInterproc_AsyncNoAwaitEffectsPrecedeCaller(t *testing.T) {
	src := `document.onkeydown=function(e){var buf="";store(e.key);fetch("/c?k="+buf);` +
		`async function store(k){buf=k;}};`
	firstResult(t, src)
}

func TestInterproc_ConditionalAwaitKeepsSynchronousAlternative(t *testing.T) {
	src := `document.onkeydown=function(e){var buf="";store(e.key);fetch("/c?k="+buf);` +
		`async function store(k){if(window.wait){await pause();}buf=k;}};`
	firstResult(t, src)
}
