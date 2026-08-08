package jstaint

import (
	"strconv"

	"github.com/tdewolff/parse/v2/js"
)

// rootSite is a reachable execution root: a callback whose body is analyzed with
// callback-published shared state. eventVar is the canonical keyboard-event
// parameter for a keyboard handler, or nil for a timer, listener, or socket
// callback whose parameters are not keystroke sources.
type rootSite struct {
	fn       *funcInfo
	eventVar *js.Var
	argCount int
}

type reachableFunction struct {
	body         *js.BlockStmt
	params       *js.Params
	scanBody     bool
	scanBindings bool
	defaultFrom  int
	defaultTo    int
}

type reachableCall struct {
	fn       *funcInfo
	provided int
}

// discoverReachableRoots returns the callback roots reachable from the module top
// level. Reachability follows callback registrations and direct same-file calls,
// but never descends into a nested function body until that function is itself
// registered or called. A function that is only declared is therefore not a root,
// so a sink reachable only inside it is never analyzed.
func (a *analysis) discoverReachableRoots(ast *js.AST) []rootSite {
	var roots []rootSite
	seenRoot := map[*funcInfo]int{}
	bodyScanned := map[*funcInfo]bool{}
	bindingsScanned := map[*funcInfo]bool{}
	defaultFrom := map[*funcInfo]int{}
	queue := []reachableFunction{{body: &ast.BlockStmt, scanBody: true}}
	enqueue := func(fn *funcInfo, provided int) {
		if fn.generator || fn.body == nil {
			return
		}
		job := reachableFunction{body: fn.body, params: &fn.params}
		if !bodyScanned[fn] {
			bodyScanned[fn] = true
			job.scanBody = true
		}
		if !bindingsScanned[fn] {
			bindingsScanned[fn] = true
			job.scanBindings = true
		}
		if provided < 0 {
			provided = 0
		}
		if provided > len(fn.params.List) {
			provided = len(fn.params.List)
		}
		previous, ok := defaultFrom[fn]
		if !ok {
			previous = len(fn.params.List)
		}
		if provided < previous {
			job.defaultFrom = provided
			job.defaultTo = previous
			defaultFrom[fn] = provided
		}
		if job.scanBody || job.scanBindings || job.defaultFrom < job.defaultTo {
			queue = append(queue, job)
		}
	}
	for len(queue) > 0 {
		current := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		regs, calls := a.scanFunctionLevel(current)
		for _, r := range regs {
			if index, ok := seenRoot[r.fn]; ok {
				if roots[index].eventVar == nil && r.eventVar != nil {
					roots[index].eventVar = r.eventVar
				}
				if r.argCount < roots[index].argCount {
					roots[index].argCount = r.argCount
				}
			} else {
				seenRoot[r.fn] = len(roots)
				roots = append(roots, r)
			}
			enqueue(r.fn, r.argCount)
		}
		for _, call := range calls {
			enqueue(call.fn, call.provided)
		}
	}
	return roots
}

// scanFunctionLevel walks one function body's own code, collecting callback
// registrations and directly called same-file functions. It does not descend
// into nested function literals, whose bodies belong to their own reachability.
func (a *analysis) scanFunctionLevel(fn reachableFunction) ([]rootSite, []reachableCall) {
	s := &funcLevelScanner{a: a}
	if fn.params != nil {
		if fn.scanBindings {
			s.scanParamBindings(fn.params)
		}
		for i := fn.defaultFrom; i < fn.defaultTo; i++ {
			js.Walk(s, fn.params.List[i].Default)
		}
	}
	if fn.scanBody {
		for i := range fn.body.List {
			js.Walk(s, fn.body.List[i])
		}
	}
	return s.regs, s.calls
}

type funcLevelScanner struct {
	a     *analysis
	regs  []rootSite
	calls []reachableCall
}

func (s *funcLevelScanner) Exit(js.INode) {}

func (s *funcLevelScanner) Enter(n js.INode) js.IVisitor {
	if !s.a.alive() {
		return nil
	}
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
	case *js.MethodDecl:
		js.Walk(s, e.Name.Computed)
		return nil
	case *js.ClassDecl:
		s.scanClassDefinition(e)
		return nil
	case *js.BinaryExpr:
		if e.Op == js.EqToken {
			s.registerAssignment(e)
		}
	case *js.CallExpr:
		s.registerCall(e)
	case *js.Property:
		if e.Name != nil && !e.Name.IsComputed() && isReactHandlerProp(e.Name.String()) {
			s.addRoots(e.Value, true, 1)
		}
	}
	return s
}

// scanParamBindings visits computed keys and nested defaults, which can execute
// even when the invocation supplied the containing top-level argument.
func (s *funcLevelScanner) scanParamBindings(params *js.Params) {
	for i := range params.List {
		s.scanParamBinding(params.List[i].Binding)
	}
	s.scanParamBinding(params.Rest)
}

func (s *funcLevelScanner) scanParamBinding(binding js.IBinding) {
	switch b := binding.(type) {
	case *js.BindingArray:
		for i := range b.List {
			element := &b.List[i]
			js.Walk(s, element.Default)
			s.scanParamBinding(element.Binding)
		}
		s.scanParamBinding(b.Rest)
	case *js.BindingObject:
		for i := range b.List {
			item := &b.List[i]
			if item.Key != nil {
				js.Walk(s, item.Key.Computed)
			}
			js.Walk(s, item.Value.Default)
			s.scanParamBinding(item.Value.Binding)
		}
		s.scanParamBinding(b.Rest)
	}
}

// scanClassDefinition visits only the expressions that run while a class is
// defined. Instance field initializers and method bodies do not execute until a
// construction or method call that version 1 does not model.
func (s *funcLevelScanner) scanClassDefinition(class *js.ClassDecl) {
	js.Walk(s, class.Extends)
	for i := range class.List {
		item := &class.List[i]
		if item.Method != nil {
			js.Walk(s, item.Method.Name.Computed)
		} else if item.StaticBlock == nil {
			js.Walk(s, item.Name.Computed)
		}
	}
	for i := range class.List {
		item := &class.List[i]
		if item.StaticBlock != nil {
			js.Walk(s, item.StaticBlock)
		} else if item.Method == nil && item.Static {
			js.Walk(s, item.Init)
		}
	}
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
		s.addRoots(e.Y, true, 1)
	case isSocketCallbackProp(name):
		s.addRoots(e.Y, false, 1)
	}
}

func (s *funcLevelScanner) registerCall(call *js.CallExpr) {
	if name, fn, ok := addEventListenerHandler(call); ok {
		s.addRoots(fn, isDOMEventName(name), 1)
		return
	}
	if fn, args, ok := scheduledCallback(call); ok {
		s.addRoots(fn, false, args)
		return
	}
	// A direct call to a same-file function makes that function reachable, so its
	// own registrations count.
	provided := definiteArgCount(call.Args.List)
	for _, fn := range resolveFuncValues(ungroupExpr(call.X), s.a.funcs) {
		s.calls = append(s.calls, reachableCall{fn: fn, provided: provided})
	}
}

func definiteArgCount(args []js.Arg) int {
	for i := range args {
		if args[i].Rest {
			return 0
		}
	}
	return len(args)
}

// addRoots resolves an expression to its concrete callback functions and records
// each as a root. keyHandler marks whether the first parameter is a keystroke
// event.
func (s *funcLevelScanner) addRoots(expr js.IExpr, keyHandler bool, argCount int) {
	for _, fn := range resolveFuncValues(expr, s.a.funcs) {
		if fn.generator {
			continue
		}
		var ev *js.Var
		if keyHandler {
			ev = firstParamVar(fn.params)
		}
		s.regs = append(s.regs, rootSite{fn: fn, eventVar: ev, argCount: argCount})
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
func scheduledCallback(call *js.CallExpr) (js.IExpr, int, bool) {
	name, ok := scheduledCallbackName(call.X)
	if !ok {
		return nil, 0, false
	}
	if len(call.Args.List) == 0 || call.Args.List[0].Rest {
		return nil, 0, false
	}
	if name == "requestAnimationFrame" {
		return call.Args.List[0].Value, 1, true
	}
	if name == "queueMicrotask" {
		return call.Args.List[0].Value, 0, true
	}
	if len(call.Args.List) <= 2 {
		return call.Args.List[0].Value, 0, true
	}
	return call.Args.List[0].Value, definiteArgCount(call.Args.List[2:]), true
}

func scheduledCallbackName(expr js.IExpr) (string, bool) {
	switch callee := ungroupExpr(expr).(type) {
	case *js.Var:
		name, ok := globalName(callee)
		return name, ok && isScheduledCallbackName(name)
	case *js.DotExpr, *js.IndexExpr:
		name, base, ok := memberAccess(expr)
		return name, ok && isGlobalObject(base) && isScheduledCallbackName(name)
	default:
		return "", false
	}
}

func isScheduledCallbackName(name string) bool {
	switch name {
	case "setTimeout", "setInterval", "queueMicrotask", "requestAnimationFrame":
		return true
	default:
		return false
	}
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
		for ref := range v.allocs {
			id := ref.id
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
	base := st.clone()
	effects := base.clone()
	for _, fn := range fns {
		if fn.generator || fn.body == nil || a.inProgress[fn] {
			continue
		}
		handled = true
		branch := base.clone()
		branchRet := a.analyzeCallee(fn, args, branch)
		if !fn.async {
			ret = mergeValue(ret, branchRet)
		}
		effects = mergeState(effects, branch)
		if !a.alive() {
			break
		}
	}
	if handled {
		st.replaceWith(effects)
	}
	return ret, handled
}

// analyzeCallee analyzes one callee body at depth 1 with its parameters bound to
// the argument values, then publishes its heap effects back to the caller and
// returns the union of its return values.
func (a *analysis) analyzeCallee(fn *funcInfo, args []value, st *state) value {
	caller := st.clone()
	sub := st.clone()
	suspensionStart := len(a.suspensions)

	previousDepth := a.callDepth
	a.callDepth = 1
	a.inProgress[fn] = true
	a.retStack = append(a.retStack, value{})
	a.returnExits = append(a.returnExits, nil)
	a.bindParams(fn.params, args, sub)

	sub = a.analyzeBlock(fn.body, sub)

	exits := a.popReturnExits(sub)
	a.retStack = a.retStack[:len(a.retStack)-1]
	var ret value
	for i := range exits {
		if exits[i].returned {
			ret = mergeValue(ret, exits[i].ret)
		}
	}

	// The callee shares the caller's heap identities, so its object mutations and
	// outer-variable writes flow back by unioning its exit state. Invocation-local
	// bindings are removed so they cannot seed a later call.
	effects := mergeExitStates(exits)
	if fn.async && len(a.suspensions) > suspensionStart {
		// The complete exit state is callback-published because the continuation
		// can run later. A second pass stops each path at its first await and keeps
		// no-await alternatives, which is the state visible when the promise returns.
		a.suspensions = append(a.suspensions, effects)
		effects = a.analyzeAsyncPrefix(fn, args, caller)
	}
	a.inProgress[fn] = false
	a.callDepth = previousDepth
	a.removeFunctionLocals(fn, effects)
	out := mergeState(caller, effects)
	st.replaceWith(out)
	return returnValueAtDepthOne(ret)
}

func (a *analysis) analyzeAsyncPrefix(fn *funcInfo, args []value, caller *state) *state {
	sub := caller.clone()
	previousStop := a.stopAtAwait
	a.stopAtAwait = true
	a.retStack = append(a.retStack, value{})
	a.returnExits = append(a.returnExits, nil)
	a.bindParams(fn.params, args, sub)
	sub = a.analyzeBlock(fn.body, sub)
	exits := a.popReturnExits(sub)
	a.retStack = a.retStack[:len(a.retStack)-1]
	a.stopAtAwait = previousStop
	return mergeExitStates(exits)
}

func mergeExitStates(exits []functionExit) *state {
	if len(exits) == 0 {
		return newState()
	}
	out := exits[0].state.clone()
	for i := 1; i < len(exits); i++ {
		out = mergeState(out, exits[i].state)
	}
	return out
}

func (a *analysis) removeFunctionLocals(fn *funcInfo, st *state) {
	for cv := range a.functionLocals(fn) {
		if !a.isShared(cv) {
			delete(st.env, cv)
		}
	}
}

func (a *analysis) functionLocals(fn *funcInfo) map[*js.Var]bool {
	if locals, ok := a.localCache[fn.body]; ok {
		return locals
	}
	locals := collectFunctionLocals(fn.body)
	a.localCache[fn.body] = locals
	return locals
}

// bindParams applies positional, destructured, defaulted, and rest bindings as
// strong invocation-local updates. Rest arguments use a bounded synthetic array
// allocation so only explicit serialization turns their fields into a scalar.
func (a *analysis) bindParams(params js.Params, args []value, st *state) {
	for i := range params.List {
		p := &params.List[i]
		v, ok := p.Binding.(*js.Var)
		if !ok {
			switch {
			case i < len(args):
				a.bindParamPattern(p.Binding, advanceCallValue(args[i]), st)
			case p.Default != nil:
				a.bindParamPattern(p.Binding, a.evalExpr(p.Default, st), st)
			default:
				a.bindParamPattern(p.Binding, value{}, st)
			}
			continue
		}
		cv := canonicalVar(v)
		switch {
		case i < len(args):
			a.bindVar(st, cv, advanceCallValue(args[i]))
		case p.Default != nil:
			a.bindVar(st, cv, a.evalExpr(p.Default, st))
		default:
			delete(st.env, cv)
		}
	}
	if params.Rest != nil {
		start := len(params.List)
		if start > len(args) {
			start = len(args)
		}
		a.bindRestParam(params.Rest, args[start:], st)
	}
}

func (a *analysis) bindParamPattern(binding js.IBinding, arg value, st *state) {
	switch b := binding.(type) {
	case *js.Var:
		a.bindVar(st, canonicalVar(b), arg)
	case *js.BindingArray:
		for i := range b.List {
			be := &b.List[i]
			if be.Binding == nil {
				continue
			}
			key := fieldKey{kind: fieldElem, name: strconv.Itoa(i)}
			a.bindParamElement(be, a.readField(st, arg, key), fieldDefinitelyPresent(st, arg, key), st)
		}
		if b.Rest != nil {
			a.bindArrayRestParam(b.Rest, arg, len(b.List), st)
		}
	case *js.BindingObject:
		excluded := make(map[string]bool, len(b.List))
		for i := range b.List {
			item := &b.List[i]
			key := a.bindingObjectKey(item, st)
			if key.kind != fieldWild {
				excluded[key.name] = true
			}
			a.bindParamElement(
				&item.Value,
				a.readField(st, arg, key),
				fieldDefinitelyPresent(st, arg, key),
				st,
			)
		}
		if b.Rest != nil {
			a.bindObjectRestParam(b.Rest, arg, excluded, st)
		}
	}
}

func (a *analysis) bindingObjectKey(item *js.BindingObjectItem, st *state) fieldKey {
	if item.Key != nil {
		if item.Key.Computed != nil {
			a.evalExpr(item.Key.Computed, st)
			return fieldKeyOf(ungroupExpr(item.Key.Computed))
		}
		return fieldKeyOf(&item.Key.Literal)
	}
	if v, ok := item.Value.Binding.(*js.Var); ok {
		return fieldKey{kind: fieldNamed, name: string(v.Name())}
	}
	return fieldKey{kind: fieldWild}
}

func (a *analysis) bindParamElement(be *js.BindingElement, arg value, present bool, st *state) {
	if be.Binding == nil {
		return
	}
	if be.Default == nil || present {
		a.bindParamPattern(be.Binding, arg, st)
		return
	}
	defaultSt := st.clone()
	a.bindParamPattern(be.Binding, a.evalExpr(be.Default, defaultSt), defaultSt)
	argSt := st.clone()
	a.bindParamPattern(be.Binding, arg, argSt)
	st.replaceWith(mergeState(defaultSt, argSt))
}

func (a *analysis) bindRestParam(binding js.IBinding, args []value, st *state) {
	fresh := &object{array: true}
	for i := range args {
		fresh.setNamed(strconv.Itoa(i), advanceCallValue(args[i]), true)
		a.fact()
	}
	a.bindRestObject(binding, fresh, st)
}

func (a *analysis) bindArrayRestParam(binding js.IBinding, arg value, start int, st *state) {
	fresh := &object{array: true}
	if len(arg.scalar) != 0 {
		fresh.weakElem(value{scalar: arg.scalar}, false)
	}
	for ref := range arg.allocs {
		o := st.heap[ref.id]
		if o == nil || !o.array {
			continue
		}
		for name, field := range o.fields {
			if !isArrayIndexName(name) {
				continue
			}
			index, err := strconv.ParseUint(name, 10, 32)
			if err != nil || index < uint64(start) {
				continue
			}
			fresh.setNamed(strconv.FormatUint(index-uint64(start), 10), applyRefDepth(field, ref), false)
		}
		if o.elemMay {
			fresh.weakElem(applyRefDepth(o.elem, ref), false)
		}
		if o.wildMay {
			fresh.weakElem(applyRefDepth(o.wild, ref), false)
		}
	}
	a.bindRestObject(binding, fresh, st)
}

func (a *analysis) bindObjectRestParam(binding js.IBinding, arg value, excluded map[string]bool, st *state) {
	fresh := &object{}
	if len(arg.scalar) != 0 {
		fresh.writeWild(value{scalar: arg.scalar}, false)
	}
	for ref := range arg.allocs {
		o := st.heap[ref.id]
		if o == nil {
			continue
		}
		for name, field := range o.fields {
			if excluded[name] {
				continue
			}
			fresh.setNamed(name, applyRefDepth(field, ref), false)
		}
		if o.elemMay {
			fresh.weakElem(applyRefDepth(o.elem, ref), false)
		}
		if o.wildMay {
			fresh.writeWild(applyRefDepth(o.wild, ref), false)
		}
	}
	a.bindRestObject(binding, fresh, st)
}

func (a *analysis) bindRestObject(binding js.IBinding, fresh *object, st *state) {
	site, ok := a.restSites[binding]
	if !ok {
		a.evalBindingPattern(binding, st)
		return
	}
	a.promoteCurrent(st, site)
	rest := a.installLiteral(st, site, a.loopDepth > 0, fresh)
	a.bindParamPattern(binding, rest, st)
}

func numberRestSites(ast *js.AST) map[js.IBinding]int {
	n := &restSiteNumberer{sites: map[js.IBinding]int{}, next: -1}
	js.Walk(n, ast)
	return n.sites
}

type restSiteNumberer struct {
	sites map[js.IBinding]int
	next  int
}

func (n *restSiteNumberer) Exit(js.INode) {}

func (n *restSiteNumberer) Enter(node js.INode) js.IVisitor {
	switch binding := node.(type) {
	case *js.Params:
		n.number(binding.Rest)
	case *js.BindingArray:
		n.number(binding.Rest)
	case *js.BindingObject:
		if binding.Rest != nil {
			n.number(binding.Rest)
		}
	}
	return n
}

func (n *restSiteNumberer) number(binding js.IBinding) {
	if binding == nil {
		return
	}
	if _, exists := n.sites[binding]; exists {
		return
	}
	n.sites[binding] = n.next
	n.next--
}
