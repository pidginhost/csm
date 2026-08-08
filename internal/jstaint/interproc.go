package jstaint

import "github.com/tdewolff/parse/v2/js"

// rootSite is a reachable execution root: a callback whose body is analyzed with
// callback-published shared state. eventVar is the canonical keyboard-event
// parameter for a keyboard handler, or nil for a timer, listener, or socket
// callback whose parameters are not keystroke sources.
type rootSite struct {
	fn       *funcInfo
	eventVar *js.Var
}

// discoverReachableRoots returns the callback roots reachable from the module top
// level. Reachability follows callback registrations and direct same-file calls,
// but never descends into a nested function body until that function is itself
// registered or called. A function that is only declared is therefore not a root,
// so a sink reachable only inside it is never analyzed.
func (a *analysis) discoverReachableRoots(ast *js.AST) []rootSite {
	var roots []rootSite
	seenRoot := map[*funcInfo]bool{}
	scanned := map[*funcInfo]bool{}
	queue := []*js.BlockStmt{&ast.BlockStmt}
	for len(queue) > 0 {
		body := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		regs, calls := a.scanFunctionLevel(body)
		for _, r := range regs {
			if !seenRoot[r.fn] {
				seenRoot[r.fn] = true
				roots = append(roots, r)
			}
			if r.fn.body != nil && !scanned[r.fn] {
				scanned[r.fn] = true
				queue = append(queue, r.fn.body)
			}
		}
		for _, fn := range calls {
			if fn.body != nil && !scanned[fn] {
				scanned[fn] = true
				queue = append(queue, fn.body)
			}
		}
	}
	return roots
}

// scanFunctionLevel walks one function body's own code, collecting callback
// registrations and directly called same-file functions. It does not descend
// into nested function literals, whose bodies belong to their own reachability.
func (a *analysis) scanFunctionLevel(body *js.BlockStmt) ([]rootSite, []*funcInfo) {
	s := &funcLevelScanner{a: a}
	for i := range body.List {
		js.Walk(s, body.List[i])
	}
	return s.regs, s.calls
}

type funcLevelScanner struct {
	a     *analysis
	regs  []rootSite
	calls []*funcInfo
}

func (s *funcLevelScanner) Exit(js.INode) {}

func (s *funcLevelScanner) Enter(n js.INode) js.IVisitor {
	if walkComputedClassName(s, n) {
		return s
	}
	switch e := n.(type) {
	case *js.FuncDecl:
		// A nested function's body is reachable only when it is registered or
		// called, which is decided at this level, not by lexical nesting.
		return nil
	case *js.ArrowFunc:
		return nil
	case *js.BinaryExpr:
		if e.Op == js.EqToken {
			s.registerAssignment(e)
		}
	case *js.CallExpr:
		s.registerCall(e)
	case *js.Property:
		if e.Name != nil && !e.Name.IsComputed() && isReactHandlerProp(e.Name.String()) {
			s.addRoots(e.Value, true)
		}
	}
	return s
}

// registerAssignment records a callback assigned to a DOM keyboard on-property or
// to a static onopen/onmessage socket property.
func (s *funcLevelScanner) registerAssignment(e *js.BinaryExpr) {
	name, _, ok := memberAccess(e.X)
	if !ok {
		return
	}
	switch {
	case isDOMHandlerProp(name):
		s.addRoots(e.Y, true)
	case isSocketCallbackProp(name):
		s.addRoots(e.Y, false)
	}
}

func (s *funcLevelScanner) registerCall(call *js.CallExpr) {
	if name, fn, ok := addEventListenerHandler(call); ok {
		s.addRoots(fn, isDOMEventName(name))
		return
	}
	if fn, ok := scheduledCallback(call); ok {
		s.addRoots(fn, false)
		return
	}
	// A direct call to a same-file function makes that function reachable, so its
	// own registrations count.
	s.calls = append(s.calls, resolveFuncValues(ungroupExpr(call.X), s.a.funcs)...)
}

// addRoots resolves an expression to its concrete callback functions and records
// each as a root. keyHandler marks whether the first parameter is a keystroke
// event.
func (s *funcLevelScanner) addRoots(expr js.IExpr, keyHandler bool) {
	for _, fn := range resolveFuncValues(expr, s.a.funcs) {
		if fn.generator {
			continue
		}
		var ev *js.Var
		if keyHandler {
			ev = firstParamVar(fn.params)
		}
		s.regs = append(s.regs, rootSite{fn: fn, eventVar: ev})
	}
}

// isSocketCallbackProp reports whether a property assignment installs a socket
// event callback. Receiver provenance is refined later; here it only widens the
// reachable set, and findings still require a keystroke to reach a sink.
func isSocketCallbackProp(name string) bool {
	switch name {
	case "onopen", "onmessage":
		return true
	default:
		return false
	}
}

// scheduledCallback returns the function scheduled by a timer or microtask
// registration whose first argument is a callback.
func scheduledCallback(call *js.CallExpr) (js.IExpr, bool) {
	v, ok := ungroupExpr(call.X).(*js.Var)
	if !ok || !isGlobalRefAny(v, "setTimeout", "setInterval", "queueMicrotask", "requestAnimationFrame") {
		return nil, false
	}
	if len(call.Args.List) == 0 || call.Args.List[0].Rest {
		return nil, false
	}
	return call.Args.List[0].Value, true
}

func isGlobalRefAny(v *js.Var, names ...string) bool {
	for _, n := range names {
		if isGlobalRef(v, n) {
			return true
		}
	}
	return false
}

// sharedState projects a state onto its file-scope portion: the shared variables
// plus the heap reachable from them. This is the may-state that callbacks publish
// to and consume from one another.
func (a *analysis) sharedState(src *state) *state {
	out := newState()
	var roots []value
	for cv, v := range src.env {
		if a.isShared(cv) {
			out.env[cv] = v
			roots = append(roots, v)
		}
	}
	copyReachableHeap(src, out, roots)
	return out
}

// publishShared merges a callback's exit shared writes into the global may-state
// and returns the updated may-state.
func (a *analysis) publishShared(global, src *state) *state {
	out := global.clone()
	var roots []value
	for cv, v := range src.env {
		if !a.isShared(cv) {
			continue
		}
		if ex, ok := out.env[cv]; ok {
			out.env[cv] = mergeValue(ex, v)
		} else {
			out.env[cv] = v
		}
		roots = append(roots, v)
	}
	mergeReachableHeap(src, out, roots)
	return out
}

func (a *analysis) isShared(cv *js.Var) bool {
	return a.sharedVars[cv] || cv.Decl == js.NoDecl
}

// copyReachableHeap copies into dst every heap object reachable from the given
// values in src.
func copyReachableHeap(src, dst *state, roots []value) {
	for _, id := range reachableAllocs(src, roots) {
		if o := src.heap[id]; o != nil {
			dst.heap[id] = o.clone()
		}
	}
}

// mergeReachableHeap merges into dst every heap object reachable from the given
// values in src, unioning with any object already present.
func mergeReachableHeap(src, dst *state, roots []value) {
	for _, id := range reachableAllocs(src, roots) {
		o := src.heap[id]
		if o == nil {
			continue
		}
		if ex, ok := dst.heap[id]; ok {
			dst.heap[id] = mergeObject(ex, o)
		} else {
			dst.heap[id] = o.clone()
		}
	}
}

// reachableAllocs returns every allocation reachable from roots through the heap.
func reachableAllocs(st *state, roots []value) []allocID {
	seen := map[allocID]bool{}
	var order []allocID
	var stack []allocID
	push := func(v value) {
		for id := range v.allocs {
			if !seen[id] {
				seen[id] = true
				order = append(order, id)
				stack = append(stack, id)
			}
		}
	}
	for _, v := range roots {
		push(v)
	}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		o := st.heap[id]
		if o == nil {
			continue
		}
		for _, fv := range o.fields {
			push(fv)
		}
		push(o.elem)
		push(o.wild)
		push(o.wildReq)
	}
	return order
}

// evalUserCall inlines a same-file function call at depth 1. It returns the
// call's tainted return value and true when the callee is a modeled user
// function; otherwise it returns false so the caller falls back to built-in
// handling. A fact already at depth 1 cannot enter another callee.
func (a *analysis) evalUserCall(callee js.IExpr, args []value, st *state) (value, bool) {
	if a.callDepth != 0 {
		return value{}, false
	}
	fns := resolveFuncValues(callee, a.funcs)
	if len(fns) == 0 {
		return value{}, false
	}
	var ret value
	handled := false
	for _, fn := range fns {
		if fn.generator || fn.async || fn.body == nil || a.inProgress[fn] {
			continue
		}
		handled = true
		ret = mergeValue(ret, a.analyzeCallee(fn, args, st))
		if !a.alive() {
			break
		}
	}
	return ret, handled
}

// analyzeCallee analyzes one callee body at depth 1 with its parameters bound to
// the argument values, then publishes its heap effects back to the caller and
// returns the union of its return values.
func (a *analysis) analyzeCallee(fn *funcInfo, args []value, st *state) value {
	sub := st.clone()
	a.bindParams(fn.params, args, sub)

	a.callDepth = 1
	a.inProgress[fn] = true
	a.retStack = append(a.retStack, value{})

	a.analyzeBlock(fn.body, sub)

	ret := a.retStack[len(a.retStack)-1]
	a.retStack = a.retStack[:len(a.retStack)-1]
	a.inProgress[fn] = false
	a.callDepth = 0

	// The callee shares the caller's heap identities, so its object mutations and
	// shared-variable writes flow back by unioning its exit state.
	st.replaceWith(mergeState(st, sub))
	return ret
}

// bindParams binds positional parameters to argument values as strong updates. A
// rest parameter and destructured parameters do not bind a scalar in version 1;
// their default expressions still execute for side effects.
func (a *analysis) bindParams(params js.Params, args []value, st *state) {
	for i := range params.List {
		p := &params.List[i]
		v, ok := p.Binding.(*js.Var)
		if !ok {
			if p.Default != nil {
				a.evalExpr(p.Default, st)
			}
			a.evalBindingPattern(p.Binding, st)
			continue
		}
		cv := canonicalVar(v)
		switch {
		case i < len(args):
			a.bindVar(st, cv, args[i])
		case p.Default != nil:
			a.bindVar(st, cv, a.evalExpr(p.Default, st))
		default:
			delete(st.env, cv)
		}
	}
	if params.Rest != nil {
		a.evalBindingPattern(params.Rest, st)
	}
}
