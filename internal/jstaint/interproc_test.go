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
