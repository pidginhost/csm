package jstaint

import "github.com/tdewolff/parse/v2/js"

// Sink display strings. They are stable because they appear in deterministic
// evidence output.
const (
	sinkFetchURL      = "fetch url argument"
	sinkFetchBody     = "fetch body option"
	sinkFetchReferrer = "fetch referrer option"
	sinkBeaconURL     = "navigator.sendBeacon url argument"
	sinkBeaconData    = "navigator.sendBeacon data argument"
)

// evalCall evaluates a call's receiver and arguments once, records any network
// sink the call represents, and returns the value the call propagates.
func (a *analysis) evalCall(call *js.CallExpr, st *state) value {
	callee := ungroupExpr(call.X)
	recv := a.evalCallCallee(callee, st)
	st.setCapture(call, recv)
	isFetch := a.isGlobalCallee(callee, "fetch")
	isBeacon := a.isBeaconCallee(callee)

	argsSt := st
	argsMayBeSkipped := call.Optional || optionalChainMaySkip(call.X)
	if argsMayBeSkipped {
		argsSt = st.clone()
	}
	args := make([]value, len(call.Args.List))
	for i := range call.Args.List {
		if isFetch && i == 1 {
			a.evalFetchInit(call, args[0], call.Args.List[i].Value, argsSt)
			continue
		}
		args[i] = a.evalExpr(call.Args.List[i].Value, argsSt)
	}
	if argsMayBeSkipped {
		st.replaceWith(mergeState(st, argsSt))
	}
	recv = st.captures[call]
	st.delCapture(call)

	a.checkCallSink(call, args, isFetch, isBeacon)
	if a.xhrOrWSMethod(call, recv, args, st) {
		return value{}
	}
	if v, ok := a.createElementValue(call, st); ok {
		return v
	}
	if ret, ok := a.evalUserCall(callee, args, st); ok {
		return ret
	}
	return a.evalCallReturn(st, callee, args, recv)
}

func optionalChainMaySkip(expr js.IExpr) bool {
	switch x := expr.(type) {
	case *js.DotExpr:
		return x.Optional || optionalChainMaySkip(x.X)
	case *js.IndexExpr:
		return x.Optional || optionalChainMaySkip(x.X)
	case *js.CallExpr:
		return x.Optional || optionalChainMaySkip(x.X)
	case *js.TemplateExpr:
		return x.Optional || optionalChainMaySkip(x.Tag)
	default:
		return false
	}
}

// evalCallCallee evaluates a call's receiver and returns its value, which the
// array-method and string-method handling consume.
func (a *analysis) evalCallCallee(callee js.IExpr, st *state) value {
	switch c := callee.(type) {
	case *js.DotExpr:
		return a.evalExpr(c.X, st)
	case *js.IndexExpr:
		recv := a.evalExpr(c.X, st)
		st.setCapture(c, recv)
		if c.Optional || optionalChainMaySkip(c.X) {
			skipped := st.clone()
			taken := st.clone()
			a.evalExpr(c.Y, taken)
			st.replaceWith(mergeState(skipped, taken))
		} else {
			a.evalExpr(c.Y, st)
		}
		recv = st.captures[c]
		st.delCapture(c)
		return recv
	default:
		a.evalExpr(callee, st)
		return value{}
	}
}

// checkCallSink records a finding when a network-call sink receives a tainted
// scalar. Only the scalar part of an argument counts: a URL or data argument must
// be a string, so an unserialized object never taints a sink.
func (a *analysis) checkCallSink(call *js.CallExpr, args []value, isFetch, isBeacon bool) {
	if isFetch {
		if len(args) >= 1 {
			a.recordURL(args[0], call, 0, sinkFetchURL)
		}
		return
	}
	if isBeacon {
		if len(args) >= 1 {
			a.recordURL(args[0], call, 0, sinkBeaconURL)
		}
		if len(args) >= 2 {
			a.recordBody(argValue(args, 0), args[1], call, 1, sinkBeaconData)
		}
	}
}

// evalFetchInit records a tainted scalar body or referrer in fetch's second
// argument, which must be a plain object literal in version 1. Evaluating the
// literal through the heap preserves computed, spread, and duplicate-property
// semantics without evaluating any property twice.
func (a *analysis) evalFetchInit(call *js.CallExpr, dest value, initExpr js.IExpr, st *state) {
	_, ok := ungroupExpr(initExpr).(*js.ObjectExpr)
	if !ok {
		a.evalExpr(initExpr, st)
		return
	}
	init := a.evalExpr(initExpr, st)
	body := a.readField(st, init, fieldKey{kind: fieldNamed, name: "body"})
	referrer := a.readField(st, init, fieldKey{kind: fieldNamed, name: "referrer"})
	a.recordBody(dest, body, call, 1, sinkFetchBody)
	a.recordBody(dest, referrer, call, 1, sinkFetchReferrer)
}

// evalCallReturn returns the value a call propagates for the value-preserving
// built-ins and serializers version 1 models, and applies the array-mutating
// effect of push. Any other call returns clean.
func (a *analysis) evalCallReturn(st *state, callee js.IExpr, args []value, recv value) value {
	for _, name := range []string{"String", "encodeURIComponent", "encodeURI", "escape", "btoa"} {
		if a.isGlobalCallee(callee, name) {
			return value{scalar: argScalar(args, 0)}
		}
	}

	prop, base, ok := memberAccess(callee)
	if !ok {
		return value{}
	}
	if prop == "fromCharCode" && a.isGlobalCallee(base, "String") {
		return value{scalar: unionArgScalars(args)}
	}
	if prop == "stringify" && a.isGlobalCallee(base, "JSON") {
		return value{scalar: a.serializeStringify(st, argValue(args, 0))}
	}
	switch prop {
	case "toString", "trim", "charAt", "slice", "substr", "substring":
		return value{scalar: recv.scalar}
	case "concat":
		if isDefiniteNonString(base) || (recv.allocOnly && len(recv.allocs) != 0) {
			return value{}
		}
		return value{scalar: mergeTaint(recv.scalar, unionArgScalars(args))}
	case "push":
		a.arrayPush(st, recv, args)
		return value{}
	case "join":
		return value{scalar: a.serializeArray(st, recv)}
	default:
		return value{}
	}
}

// arrayPush taints the array-element field of the receiver's allocations with the
// pushed values.
func (a *analysis) arrayPush(st *state, recv value, args []value) {
	if len(args) == 0 {
		return
	}
	v := args[0]
	for i := 1; i < len(args); i++ {
		v = mergeValue(v, args[i])
	}
	a.writeArrayElements(st, recv, v, true)
}

func (a *analysis) writeArrayElements(st *state, recv value, v value, definite bool) {
	ids := uniqueAllocIDs(recv.allocs)
	strong := len(ids) == 1 && soleCurrent(recv.allocs)
	for id := range ids {
		if o := st.heap[id]; o == nil || !o.array {
			continue
		}
		st.mutObject(id).weakElem(v, definite && strong && !id.summary)
	}
	if a.callDepth == 0 && allocsConstrained(recv.allocs) && valueCarriesDepthZero(st, v) {
		resetAllocRefDepth(st, ids)
	}
	a.fact()
}

func argValue(args []value, i int) value {
	if i >= len(args) {
		return value{}
	}
	return args[i]
}

func argScalar(args []value, i int) taintSet {
	return argValue(args, i).scalar
}

func unionArgScalars(args []value) taintSet {
	var out taintSet
	for i := range args {
		out = mergeTaint(out, args[i].scalar)
	}
	return out
}

// isDefiniteNonString reports whether concat's receiver is provably not a string,
// so array concat is not treated as string laundering.
func isDefiniteNonString(expr js.IExpr) bool {
	switch x := ungroupExpr(expr).(type) {
	case *js.LiteralExpr:
		return x.TokenType != js.StringToken
	case *js.ArrayExpr, *js.ObjectExpr, *js.NewExpr, *js.ClassDecl, *js.FuncDecl, *js.ArrowFunc:
		return true
	default:
		return false
	}
}

// isGlobalCallee reports whether callee is the named unshadowed global function,
// either bare or as a property of window/self/globalThis.
func (a *analysis) isGlobalCallee(callee js.IExpr, name string) bool {
	switch c := ungroupExpr(callee).(type) {
	case *js.Var:
		return isGlobalRef(c, name)
	case *js.DotExpr, *js.IndexExpr:
		prop, base, ok := memberAccess(callee)
		return ok && prop == name && isGlobalObject(base)
	default:
		return false
	}
}

func (a *analysis) isBeaconCallee(callee js.IExpr) bool {
	prop, base, ok := memberAccess(callee)
	return ok && prop == "sendBeacon" && a.isNavigator(base)
}

// isNavigator reports whether expr is the unshadowed global navigator object.
func (a *analysis) isNavigator(expr js.IExpr) bool {
	switch v := ungroupExpr(expr).(type) {
	case *js.Var:
		return isGlobalRef(v, "navigator")
	case *js.DotExpr, *js.IndexExpr:
		prop, base, ok := memberAccess(expr)
		return ok && prop == "navigator" && isGlobalObject(base)
	default:
		return false
	}
}

// isGlobalObject reports whether expr is one of the unshadowed global object
// aliases.
func isGlobalObject(expr js.IExpr) bool {
	v, ok := ungroupExpr(expr).(*js.Var)
	if !ok {
		return false
	}
	name, ok := globalName(v)
	if !ok {
		return false
	}
	switch name {
	case "window", "self", "globalThis":
		return true
	default:
		return false
	}
}

// globalName returns the name of an unshadowed global reference. The parser
// leaves free identifiers undeclared, so a NoDecl canonical identity is a global
// binding rather than a local of the same spelling.
func globalName(v *js.Var) (string, bool) {
	c := canonicalVar(v)
	if c.Decl != js.NoDecl {
		return "", false
	}
	return string(c.Name()), true
}
