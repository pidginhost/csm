package jstaint

import "github.com/tdewolff/parse/v2/js"

// funcInfo is a normalized view of a function expression, declaration, or arrow
// function. The two AST shapes (FuncDecl and ArrowFunc) share nothing but these
// fields for the analyzer's purposes.
type funcInfo struct {
	params    js.Params
	body      *js.BlockStmt
	generator bool
}

// handlerSite is one discovered keyboard-event handler registration. eventVar is
// the canonical identity of the handler's first parameter, or nil when that
// parameter is not a plain identifier (a destructured or absent parameter).
type handlerSite struct {
	fn       *funcInfo
	eventVar *js.Var
}

// discoverHandlers finds every statically resolvable keyboard-handler
// registration in the parse unit and returns one site per resolved function.
// When a handler identifier resolves to more than one function value, each is
// returned so their analyses can be unioned.
func discoverHandlers(ast *js.AST) []handlerSite {
	funcs := collectFuncValues(ast)
	var sites []handlerSite
	v := &handlerVisitor{funcs: funcs, add: func(fn *funcInfo) {
		sites = append(sites, handlerSite{fn: fn, eventVar: firstParamVar(fn.params)})
	}}
	js.Walk(v, ast)
	return sites
}

type handlerVisitor struct {
	funcs map[*js.Var][]*funcInfo
	add   func(*funcInfo)
}

func (v *handlerVisitor) Exit(js.INode) {}

func (v *handlerVisitor) Enter(n js.INode) js.IVisitor {
	switch e := n.(type) {
	case *js.BinaryExpr:
		if e.Op == js.EqToken && isKeyHandlerProperty(e.X) {
			v.emit(e.Y)
		}
	case *js.CallExpr:
		if name, fn, ok := addEventListenerHandler(e); ok && isDOMEventName(name) {
			v.emit(fn)
		}
	case *js.Property:
		if e.Name != nil && !e.Name.IsComputed() && isReactHandlerProp(e.Name.String()) {
			v.emit(e.Value)
		}
	}
	return v
}

// emit resolves expr to zero or more concrete functions and records a handler
// site for each. A generator is never a handler.
func (v *handlerVisitor) emit(expr js.IExpr) {
	for _, fn := range resolveFuncValues(expr, v.funcs) {
		if !fn.generator {
			v.add(fn)
		}
	}
}

// isKeyHandlerProperty reports whether target is a member access naming a DOM
// keyboard on* property, in either dot or static-bracket form.
func isKeyHandlerProperty(target js.IExpr) bool {
	name, _, ok := memberAccess(target)
	return ok && isDOMHandlerProp(name)
}

// DOM on* properties are lowercase; the DOM does not fire a camelCase
// element.onKeyDown assignment.
func isDOMHandlerProp(name string) bool {
	switch name {
	case "onkeydown", "onkeypress", "onkeyup":
		return true
	default:
		return false
	}
}

// DOM event type strings passed to addEventListener are case-sensitive
// lowercase.
func isDOMEventName(name string) bool {
	switch name {
	case "keydown", "keypress", "keyup":
		return true
	default:
		return false
	}
}

// React object-literal handler props are camelCase.
func isReactHandlerProp(name string) bool {
	switch name {
	case "onKeyDown", "onKeyPress", "onKeyUp":
		return true
	default:
		return false
	}
}

// addEventListenerHandler matches both the receiver form el.addEventListener and
// the bare unshadowed-global form, returning the event name and handler value.
func addEventListenerHandler(call *js.CallExpr) (string, js.IExpr, bool) {
	if len(call.Args.List) < 2 {
		return "", nil, false
	}
	if call.Args.List[0].Rest || call.Args.List[1].Rest {
		return "", nil, false
	}
	switch callee := call.X.(type) {
	case *js.DotExpr:
		if name, ok := staticStringOrIdent(callee.Y); !ok || name != "addEventListener" {
			return "", nil, false
		}
	case *js.Var:
		if !isGlobalRef(callee, "addEventListener") {
			return "", nil, false
		}
	default:
		return "", nil, false
	}
	eventName, ok := staticStringOrIdent(ungroupExpr(call.Args.List[0].Value))
	if !ok {
		return "", nil, false
	}
	return eventName, call.Args.List[1].Value, true
}

func ungroupExpr(expr js.IExpr) js.IExpr {
	for {
		group, ok := expr.(*js.GroupExpr)
		if !ok {
			return expr
		}
		expr = group.X
	}
}

// isGlobalRef reports whether v is an unshadowed reference to the named global
// binding. The parser leaves free identifiers undeclared, so a NoDecl canonical
// identity with the expected name is a global; a local declaration of the same
// name has a declaration type and is therefore not the platform global.
func isGlobalRef(v *js.Var, name string) bool {
	n, ok := globalName(v)
	return ok && n == name
}

func firstParamVar(params js.Params) *js.Var {
	if len(params.List) == 0 {
		return nil
	}
	if v, ok := params.List[0].Binding.(*js.Var); ok {
		return canonicalVar(v)
	}
	return nil
}

// resolveFuncValues returns the concrete functions expr can denote: a direct,
// possibly parenthesized function or arrow literal, or a same-file identifier
// whose collected values are functions.
func resolveFuncValues(expr js.IExpr, funcs map[*js.Var][]*funcInfo) []*funcInfo {
	expr = ungroupExpr(expr)
	if fn := literalFuncValue(expr); fn != nil {
		return []*funcInfo{fn}
	}
	switch e := expr.(type) {
	case *js.Var:
		return funcs[canonicalVar(e)]
	default:
		return nil
	}
}

// collectFuncValues maps each canonical variable to the function values assigned
// to it anywhere in the file: named declarations, declaration initializers, and
// plain assignments. Multiple values accumulate so a later union covers every
// possibility.
func collectFuncValues(ast *js.AST) map[*js.Var][]*funcInfo {
	c := &funcValueCollector{funcs: map[*js.Var][]*funcInfo{}}
	js.Walk(c, ast)
	return c.funcs
}

type funcValueCollector struct {
	funcs map[*js.Var][]*funcInfo
}

func (c *funcValueCollector) Exit(js.INode) {}

func (c *funcValueCollector) Enter(n js.INode) js.IVisitor {
	switch e := n.(type) {
	case *js.FuncDecl:
		if e.Name != nil {
			c.bind(e.Name, &funcInfo{params: e.Params, body: &e.Body, generator: e.Generator})
		}
	case *js.VarDecl:
		for i := range e.List {
			be := e.List[i]
			target, ok := be.Binding.(*js.Var)
			if !ok || be.Default == nil {
				continue
			}
			for _, fn := range literalFuncValues(be.Default) {
				c.bind(target, fn)
			}
		}
	case *js.BinaryExpr:
		if e.Op != js.EqToken {
			return c
		}
		if target, ok := e.X.(*js.Var); ok {
			for _, fn := range literalFuncValues(e.Y) {
				c.bind(target, fn)
			}
		}
	}
	return c
}

func (c *funcValueCollector) bind(v *js.Var, fn *funcInfo) {
	key := canonicalVar(v)
	c.funcs[key] = append(c.funcs[key], fn)
}

// literalFuncValues returns a function value only for a direct, possibly
// parenthesized function or arrow literal. It does not chase identifier aliases,
// so binding collection cannot recurse without bound.
func literalFuncValues(expr js.IExpr) []*funcInfo {
	if fn := literalFuncValue(ungroupExpr(expr)); fn != nil {
		return []*funcInfo{fn}
	}
	return nil
}

func literalFuncValue(expr js.IExpr) *funcInfo {
	switch e := expr.(type) {
	case *js.FuncDecl:
		return &funcInfo{params: e.Params, body: &e.Body, generator: e.Generator}
	case *js.ArrowFunc:
		return &funcInfo{params: e.Params, body: &e.Body}
	default:
	}
	return nil
}
