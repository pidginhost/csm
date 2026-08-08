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
// sink the call represents, and returns the taint the call propagates.
func (a *analysis) evalCall(call *js.CallExpr, e env) taintSet {
	callee := ungroupExpr(call.X)
	recvTaint := a.evalCallCallee(callee, e)
	isFetch := a.isGlobalCallee(callee, "fetch")
	isBeacon := a.isBeaconCallee(callee)

	argsEnv := e
	argsMayBeSkipped := call.Optional || optionalChainMaySkip(call.X)
	if argsMayBeSkipped {
		argsEnv = copyEnv(e)
	}
	args := make([]taintSet, len(call.Args.List))
	for i := range call.Args.List {
		if isFetch && i == 1 {
			a.evalFetchInit(call, call.Args.List[i].Value, argsEnv)
			continue
		}
		args[i] = a.evalExpr(call.Args.List[i].Value, argsEnv)
	}
	if argsMayBeSkipped {
		replaceEnv(e, mergeEnv(e, argsEnv))
	}

	a.checkCallSink(call, args, isFetch, isBeacon)
	return a.callReturn(call, args, recvTaint)
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

func (a *analysis) evalCallCallee(callee js.IExpr, e env) taintSet {
	switch c := callee.(type) {
	case *js.DotExpr:
		return a.evalExpr(c.X, e)
	case *js.IndexExpr:
		recvTaint := a.evalExpr(c.X, e)
		if c.Optional || optionalChainMaySkip(c.X) {
			skipped := copyEnv(e)
			taken := copyEnv(e)
			a.evalExpr(c.Y, taken)
			replaceEnv(e, mergeEnv(skipped, taken))
		} else {
			a.evalExpr(c.Y, e)
		}
		return recvTaint
	default:
		a.evalExpr(callee, e)
		return nil
	}
}

// checkCallSink records a finding when a network-call sink receives tainted data.
func (a *analysis) checkCallSink(call *js.CallExpr, args []taintSet, isFetch, isBeacon bool) {
	if isFetch {
		if len(args) >= 1 {
			a.record(args[0], call, 0, sinkFetchURL)
		}
		return
	}
	if isBeacon {
		if len(args) >= 1 {
			a.record(args[0], call, 0, sinkBeaconURL)
		}
		if len(args) >= 2 {
			a.record(args[1], call, 1, sinkBeaconData)
		}
	}
}

// evalFetchInit looks for a tainted scalar body or referrer in fetch's second
// argument, which must be a plain object literal in version 1.
func (a *analysis) evalFetchInit(call *js.CallExpr, initExpr js.IExpr, e env) {
	obj, ok := ungroupExpr(initExpr).(*js.ObjectExpr)
	if !ok {
		a.evalExpr(initExpr, e)
		return
	}
	var body, referrer taintSet
	a.evalObjectProperties(obj, e, func(name string, ts taintSet) {
		switch name {
		case "body":
			body = ts
		case "referrer":
			referrer = ts
		}
	})
	a.record(body, call, 1, sinkFetchBody)
	a.record(referrer, call, 1, sinkFetchReferrer)
}

// callReturn returns the taint a call propagates for the value-preserving
// built-ins version 1 models. Any other call returns clean.
func (a *analysis) callReturn(call *js.CallExpr, args []taintSet, recvTaint taintSet) taintSet {
	callee := ungroupExpr(call.X)
	for _, name := range []string{"String", "encodeURIComponent", "encodeURI", "escape", "btoa"} {
		if a.isGlobalCallee(callee, name) {
			return argTaint(args, 0)
		}
	}

	prop, baseExpr, ok := memberAccess(callee)
	if !ok {
		return nil
	}
	if prop == "fromCharCode" && a.isGlobalCallee(baseExpr, "String") {
		return unionArgs(args)
	}
	if prop == "stringify" && a.isGlobalCallee(baseExpr, "JSON") {
		return argTaint(args, 0)
	}
	switch prop {
	case "toString", "trim":
		return recvTaint
	case "charAt", "slice", "substr", "substring":
		return recvTaint
	case "concat":
		if isDefiniteNonString(baseExpr) {
			return nil
		}
		return mergeTaint(recvTaint, unionArgs(args))
	default:
		return nil
	}
}

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

func argTaint(args []taintSet, index int) taintSet {
	if index >= len(args) {
		return nil
	}
	return args[index]
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
