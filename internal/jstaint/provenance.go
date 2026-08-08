package jstaint

import "github.com/tdewolff/parse/v2/js"

// objectKind names the platform object an allocation represents. Receiver
// provenance is what separates a real network sink from a generic application
// object that merely has a method named send, open, or src.
type objectKind uint8

const (
	kindGeneric objectKind = iota
	kindXHR
	kindWebSocket
	kindResource // Image or a typed resource element from createElement
)

func mergeKind(a, b objectKind) objectKind {
	if a != kindGeneric {
		return a
	}
	return b
}

// Provenance sink display strings.
const (
	sinkXHRBody     = "XMLHttpRequest.send body argument"
	sinkXHRURL      = "XMLHttpRequest.open url argument"
	sinkXHRHeader   = "XMLHttpRequest.setRequestHeader value argument"
	sinkWSURL       = "WebSocket url argument"
	sinkWSProtocol  = "WebSocket protocols argument"
	sinkWSSend      = "WebSocket.send argument"
	sinkResourceSrc = "resource element src assignment"
)

// schemeState is the URL-scheme lattice element. The zero value is the unknown,
// possibly-networked scheme (a relative or dynamic URL). A set scheme names a
// single definite scheme; a merge of two different schemes returns to unknown.
type schemeState struct {
	set  bool
	name string
}

func mergeScheme(a, b schemeState) schemeState {
	if a == b {
		return a
	}
	return schemeState{}
}

// isNonNetworkScheme reports whether a definite scheme never performs a network
// fetch, so a captured key placed after it is not exfiltrated.
func (s schemeState) isNonNetwork() bool {
	if !s.set {
		return false
	}
	switch s.name {
	case "about", "blob", "data", "file", "javascript":
		return true
	default:
		return false
	}
}

// schemeOfLiteral extracts the definite scheme of a string literal's value. A URL
// scheme is an ASCII letter followed by letters, digits, +, -, or ., ending at
// the first colon. Anything else (a relative path, a dynamic prefix) is unknown.
func schemeOfLiteral(expr js.IExpr) schemeState {
	lit, ok := expr.(*js.LiteralExpr)
	if !ok || lit.TokenType != js.StringToken || len(lit.Data) < 2 {
		return schemeState{}
	}
	q := lit.Data[0]
	if (q != '\'' && q != '"') || lit.Data[len(lit.Data)-1] != q {
		return schemeState{}
	}
	return schemeOfBytes(lit.Data[1 : len(lit.Data)-1])
}

func schemeOfBytes(b []byte) schemeState {
	if len(b) == 0 || !isASCIILetter(b[0]) {
		return schemeState{}
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == ':' {
			if i == 0 {
				return schemeState{}
			}
			return schemeState{set: true, name: asciiFoldString(b[:i])}
		}
		if !isSchemeChar(c) {
			return schemeState{}
		}
	}
	return schemeState{}
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isSchemeChar(c byte) bool {
	return isASCIILetter(c) || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'
}

func asciiFoldString(b []byte) string {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = asciiLower(b[i])
	}
	return string(out)
}

// templateScheme reads the definite scheme from a template literal's leading
// text, or from its first substitution when no literal prefix precedes it.
func templateScheme(x *js.TemplateExpr, first schemeState) schemeState {
	if x.Tag != nil {
		return schemeState{}
	}
	if len(x.List) == 0 {
		return schemeOfBytes(templateCooked(x.Tail))
	}
	leading := templateCooked(x.List[0].Value)
	if scheme := schemeOfBytes(leading); scheme.set {
		return scheme
	}
	if len(leading) == 0 {
		return first
	}
	return schemeState{}
}

// templateCooked strips the surrounding backtick or `}`/`${` delimiters from a
// template part's raw bytes so only the literal text remains.
func templateCooked(raw []byte) []byte {
	if len(raw) > 0 && (raw[0] == '`' || raw[0] == '}') {
		raw = raw[1:]
	}
	if n := len(raw); n >= 2 && raw[n-2] == '$' && raw[n-1] == '{' {
		raw = raw[:n-2]
	} else if n >= 1 && raw[n-1] == '`' {
		raw = raw[:n-1]
	}
	return raw
}

// resourceElementTag reports whether a createElement tag names an element that
// fetches its src attribute, compared ASCII case-insensitively.
func resourceElementTag(name string) bool {
	switch asciiFoldString([]byte(name)) {
	case "audio", "embed", "iframe", "img", "script", "source", "track", "video":
		return true
	default:
		return false
	}
}

// allocateKinded installs a fresh current platform-object allocation. Recency is
// retained inside loops because constructor-local protocol state must not inherit
// from older instances; promoteCurrent still bounds each site to two identities.
func (a *analysis) allocateKinded(st *state, site int, kind objectKind) value {
	a.promoteCurrent(st, site)
	fresh := &object{kind: kind}
	return a.installLiteral(st, site, false, fresh)
}

// evalNewSink handles new-expression receivers with network provenance. It
// returns the constructed value and true when it recognized one; the caller
// evaluates arguments before calling this.
func (a *analysis) evalNewSink(x *js.NewExpr, args []value, site int, st *state) (value, bool) {
	switch {
	case a.isGlobalCallee(x.X, "XMLHttpRequest"):
		return a.allocateKinded(st, site, kindXHR), true
	case a.isGlobalCallee(x.X, "Image"):
		return a.allocateKinded(st, site, kindResource), true
	case a.isGlobalCallee(x.X, "WebSocket"):
		if len(args) == 0 {
			return value{}, true
		}
		a.recordURL(args[0], x, 0, sinkWSURL)
		if args[0].scheme.isNonNetwork() {
			return value{}, true
		}
		if len(args) >= 2 {
			a.record(argScalar(args, 1), x, 1, sinkWSProtocol)
			a.record(a.serializeArray(st, args[1]), x, 1, sinkWSProtocol)
		}
		return a.allocateKinded(st, site, kindWebSocket), true
	}
	return value{}, false
}

// createElementValue returns a typed resource-element allocation when the call is
// document.createElement with a static resource tag, and true when it applied.
func (a *analysis) createElementValue(call *js.CallExpr, st *state) (value, bool) {
	prop, base, ok := memberAccess(ungroupExpr(call.X))
	if !ok || prop != "createElement" || !a.isDocument(base) {
		return value{}, false
	}
	if len(call.Args.List) == 0 {
		return value{}, false
	}
	tag, ok := staticStringOrIdent(ungroupExpr(call.Args.List[0].Value))
	if !ok || !resourceElementTag(tag) {
		return value{}, false
	}
	site, ok := a.sites[call]
	if !ok {
		return value{}, false
	}
	return a.allocateKinded(st, site, kindResource), true
}

// isDocument reports whether expr is the unshadowed global document object.
func (a *analysis) isDocument(expr js.IExpr) bool {
	switch v := ungroupExpr(expr).(type) {
	case *js.Var:
		return isGlobalRef(v, "document")
	case *js.DotExpr, *js.IndexExpr:
		prop, base, ok := memberAccess(expr)
		return ok && prop == "document" && isGlobalObject(base)
	default:
		return false
	}
}

// xhrOrWSMethod applies a method call on an XHR or WebSocket receiver and records
// any sink. It returns true when the receiver's provenance claimed the call.
func (a *analysis) xhrOrWSMethod(call *js.CallExpr, recv value, args []value, st *state) bool {
	prop, _, ok := memberAccess(ungroupExpr(call.X))
	if !ok {
		return false
	}
	ids := xhrWSTargets(st, recv)
	if len(ids) == 0 {
		return false
	}
	strong := recv.allocOnly && len(uniqueAllocIDs(recv.allocs)) == 1 && soleCurrent(recv.allocs)
	handled := false
	for id := range ids {
		o := st.heap[id]
		switch o.kind {
		case kindXHR:
			handled = a.applyXHRMethod(st, o, prop, call, args, recv, id, strong && !id.summary) || handled
		case kindWebSocket:
			handled = a.applyWSMethod(o, prop, call, args, strong && !id.summary) || handled
		}
	}
	return handled
}

// xhrWSTargets returns the receiver allocations that carry XHR or WebSocket
// provenance.
func xhrWSTargets(st *state, recv value) map[allocID]bool {
	var ids map[allocID]bool
	for ref := range recv.allocs {
		o := st.heap[ref.id]
		if o == nil || (o.kind != kindXHR && o.kind != kindWebSocket) {
			continue
		}
		if ids == nil {
			ids = map[allocID]bool{}
		}
		ids[ref.id] = true
	}
	return ids
}

func (a *analysis) applyXHRMethod(
	st *state,
	o *object,
	prop string,
	call *js.CallExpr,
	args []value,
	recv value,
	id allocID,
	strong bool,
) bool {
	switch prop {
	case "open":
		if len(args) < 2 {
			return true
		}
		wasOpened := o.xhrOpened
		// A later open reinitializes the request. Only a lone current receiver can
		// prove the reset clears an earlier path's remembered URL and headers.
		o.xhrOpened = true
		switch {
		case strong:
			o.xhrURL = argScalar(args, 1)
			o.xhrHeader = nil
			o.xhrScheme = args[1].scheme
		case !wasOpened:
			o.xhrURL = argScalar(args, 1)
			o.xhrScheme = args[1].scheme
		default:
			o.xhrURL = mergeTaint(o.xhrURL, argScalar(args, 1))
			o.xhrScheme = mergeScheme(o.xhrScheme, args[1].scheme)
		}
		a.resetReceiverDepth(st, id, argScalar(args, 1))
		return true
	case "setRequestHeader":
		if o.xhrOpened {
			o.xhrHeader = mergeTaint(o.xhrHeader, argScalar(args, 1))
			a.resetReceiverDepth(st, id, argScalar(args, 1))
		}
		return true
	case "send":
		if o.xhrOpened && !o.xhrScheme.isNonNetwork() {
			a.record(argScalar(args, 0), call, 0, sinkXHRBody)
			a.record(receiverTaint(recv, id, o.xhrURL), call, 1, sinkXHRURL)
			a.record(receiverTaint(recv, id, o.xhrHeader), call, 2, sinkXHRHeader)
		}
		return true
	case "abort":
		if strong {
			o.xhrOpened = false
			o.xhrURL = nil
			o.xhrHeader = nil
			o.xhrScheme = schemeState{}
		}
		return true
	}
	return false
}

func (a *analysis) resetReceiverDepth(st *state, id allocID, ts taintSet) {
	if taintCarriesDepth(ts, a.callDepth) {
		resetAllocRefDepth(st, map[allocID]bool{id: true})
	}
}

// receiverTaint applies every call-depth constraint carried by receiver aliases
// to state stored on one allocation.
func receiverTaint(recv value, id allocID, ts taintSet) taintSet {
	var out taintSet
	for ref := range recv.allocs {
		if ref.id == id {
			out = mergeTaint(out, applyTaintDepth(ts, ref.minDepth, ref.advance))
		}
	}
	return out
}

func (a *analysis) applyWSMethod(o *object, prop string, call *js.CallExpr, args []value, strong bool) bool {
	switch prop {
	case "send":
		if o.wsMaybeOpen && !o.wsClosed {
			a.record(argScalar(args, 0), call, 0, sinkWSSend)
		}
		return true
	case "close":
		if strong {
			o.wsClosed = true
		}
		return true
	}
	return false
}

// markSocketsObservable marks every WebSocket allocation in a shared state as
// possibly open. A socket published to file-scope state can be observed open by a
// later callback, which is exactly when a send on it becomes a network sink.
func markSocketsObservable(st *state) {
	for _, o := range st.heap {
		if o.kind == kindWebSocket {
			o.wsMaybeOpen = true
		}
	}
}

// resourceSrcSink records a src-assignment sink when the receiver is a typed
// resource element, gated by the assigned value's URL scheme.
func (a *analysis) resourceSrcSink(recv value, key fieldKey, rhs value, node js.INode, st *state) {
	if key.kind != fieldNamed || key.name != "src" {
		return
	}
	for ref := range recv.allocs {
		if o := st.heap[ref.id]; o != nil && o.kind == kindResource {
			a.recordURL(rhs, node, 0, sinkResourceSrc)
			return
		}
	}
}

// recordURL records a destination-URL sink unless the destination is proven to
// use a non-network scheme.
func (a *analysis) recordURL(dest value, sink js.INode, arg int, text string) {
	if dest.scheme.isNonNetwork() {
		return
	}
	a.record(dest.scalar, sink, arg, text)
}

// recordBody records a body, data, or header sink carried alongside a
// destination. A proven non-network destination controls the whole operation, so
// its body is not exfiltrated either.
func (a *analysis) recordBody(dest, payload value, sink js.INode, arg int, text string) {
	if dest.scheme.isNonNetwork() {
		return
	}
	a.record(payload.scalar, sink, arg, text)
}
