package jstaint

import "github.com/tdewolff/parse/v2/js"

// Sink display strings. They are stable because they appear in deterministic
// evidence output.
const (
	sinkFetchURL   = "fetch url argument"
	sinkFetchBody  = "fetch body option"
	sinkBeaconURL  = "navigator.sendBeacon url argument"
	sinkBeaconData = "navigator.sendBeacon data argument"
)

// evalCall evaluates a call's arguments and receiver once, records any network
// sink the call represents, and returns the taint the call propagates.
func (a *analysis) evalCall(call *js.CallExpr, e env) taintSet {
	args := make([]taintSet, len(call.Args.List))
	for i := range call.Args.List {
		args[i] = a.evalExpr(call.Args.List[i].Value, e)
	}

	var recvTaint taintSet
	switch callee := ungroupExpr(call.X).(type) {
	case *js.DotExpr:
		recvTaint = a.evalExpr(callee.X, e)
	case *js.IndexExpr:
		recvTaint = a.evalExpr(callee.X, e)
		a.evalExpr(callee.Y, e)
	}

	a.checkCallSink(call, e, args)
	return a.callReturn(call, args, recvTaint)
}

// checkCallSink records a finding when a network-call sink receives tainted data.
func (a *analysis) checkCallSink(call *js.CallExpr, e env, args []taintSet) {
	callee := ungroupExpr(call.X)
	if a.isGlobalCallee(callee, "fetch") {
		if len(args) >= 1 {
			a.record(args[0], call, 0, sinkFetchURL)
		}
		if len(call.Args.List) >= 2 {
			a.checkFetchInit(call, call.Args.List[1].Value, e)
		}
		return
	}
	if dot, ok := callee.(*js.DotExpr); ok {
		if prop, ok := staticStringOrIdent(ungroupExpr(dot.Y)); ok && prop == "sendBeacon" && a.isNavigator(dot.X) {
			if len(args) >= 1 {
				a.record(args[0], call, 0, sinkBeaconURL)
			}
			if len(args) >= 2 {
				a.record(args[1], call, 1, sinkBeaconData)
			}
		}
	}
}

// checkFetchInit looks for a tainted scalar body or referrer in fetch's second
// argument, which must be a plain object literal in version 1.
func (a *analysis) checkFetchInit(call *js.CallExpr, initExpr js.IExpr, e env) {
	obj, ok := ungroupExpr(initExpr).(*js.ObjectExpr)
	if !ok {
		return
	}
	for i := range obj.List {
		p := &obj.List[i]
		if p.Name == nil || p.Name.IsComputed() {
			continue
		}
		name := p.Name.String()
		if name != "body" && name != "referrer" {
			continue
		}
		if ts := a.evalExpr(p.Value, e); len(ts) != 0 {
			text := sinkFetchBody
			if name == "referrer" {
				text = "fetch referrer option"
			}
			a.record(ts, call, 1, text)
		}
	}
}

// callReturn returns the taint a call propagates for the value-preserving
// built-ins version 1 models. Any other call returns clean.
func (a *analysis) callReturn(call *js.CallExpr, args []taintSet, recvTaint taintSet) taintSet {
	switch callee := ungroupExpr(call.X).(type) {
	case *js.Var:
		if name, ok := globalName(callee); ok {
			switch name {
			case "String", "encodeURIComponent", "encodeURI", "escape", "btoa":
				return unionArgs(args)
			}
		}
		return nil
	case *js.DotExpr:
		prop, ok := staticStringOrIdent(ungroupExpr(callee.Y))
		if !ok {
			return nil
		}
		if base, ok := ungroupExpr(callee.X).(*js.Var); ok {
			if bn, ok := globalName(base); ok {
				switch bn {
				case "String":
					if prop == "fromCharCode" {
						return unionArgs(args)
					}
				case "JSON":
					if prop == "stringify" {
						return unionArgs(args)
					}
				}
			}
		}
		if isStringMethod(prop) {
			return mergeTaint(recvTaint, unionArgs(args))
		}
		return nil
	default:
		return nil
	}
}

func isStringMethod(name string) bool {
	switch name {
	case "charAt", "slice", "substr", "substring", "toString", "trim", "concat":
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
	case *js.DotExpr:
		prop, ok := staticStringOrIdent(ungroupExpr(c.Y))
		return ok && prop == name && isGlobalObject(c.X)
	default:
		return false
	}
}

// isNavigator reports whether expr is the unshadowed global navigator object.
func (a *analysis) isNavigator(expr js.IExpr) bool {
	switch v := ungroupExpr(expr).(type) {
	case *js.Var:
		return isGlobalRef(v, "navigator")
	case *js.DotExpr:
		prop, ok := staticStringOrIdent(ungroupExpr(v.Y))
		return ok && prop == "navigator" && isGlobalObject(v.X)
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
