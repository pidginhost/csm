package jstaint

import (
	"context"
	"sort"

	"github.com/tdewolff/parse/v2/js"
)

// maxASTNodes bounds the parser nodes the structural pass visits. It is a safety
// ceiling: exceeding it fails the whole analysis rather than returning a partial
// decision.
const maxASTNodes = 200_000

// taintChain is the shortest known list of via display names a captured value
// passed through to reach a program point.
type taintChain = []string

// taintFact identifies one source at one permitted user-call depth. Depth is
// part of the fact so a returned value cannot enter a second user-defined
// callee after control returns to a root.
type taintFact struct {
	source    int
	callDepth uint8
}

// taintSet maps a source/depth fact to its shortest via chain.
type taintSet map[taintFact]taintChain

// flowKey is the identity of one source-to-sink flow: which source occurrence,
// sink occurrence, sink kind, and argument. Multiple propagation routes to the
// same endpoints collapse to one result with the shortest chain.
type flowKey struct {
	source int
	sink   js.INode
	arg    int
	kind   string
}

type sourceOccurrence struct {
	id      int
	display string
}

type functionExit struct {
	state    *state
	ret      value
	returned bool
}

// analysis holds the mutable state for one Analyze call.
type analysis struct {
	ctx         context.Context
	budget      *resourceBudget
	sources     map[js.IExpr]sourceOccurrence
	sites       map[js.INode]int
	funcs       map[*js.Var][]*funcInfo
	sharedVars  map[*js.Var]bool
	inProgress  map[*funcInfo]bool
	localCache  map[*js.BlockStmt]map[*js.Var]bool
	restSites   map[js.IBinding]int
	retStack    []value
	returnExits [][]functionExit
	suspensions []*state
	display     map[int]string
	results     map[flowKey]Result
	loopDepth   int
	callDepth   int
	stopAtAwait bool
	err         error
}

// taintPass is the production analysis pass wired into Analyze. It first enforces
// the structural depth, node, and cancellation limits with a bounded walk, then
// runs the taint analysis on the within-limit tree.
func taintPass(ctx context.Context, ast *js.AST, budget *resourceBudget) ([]Result, int, bool, error) {
	lv := &limitVisitor{ctx: ctx, budget: budget}
	js.Walk(lv, ast)
	if lv.err != nil {
		return nil, 0, false, lv.err
	}

	sharedVars := map[*js.Var]bool{}
	for _, v := range ast.Declared {
		sharedVars[canonicalVar(v)] = true
	}
	a := &analysis{
		ctx:        ctx,
		budget:     budget,
		sites:      numberAllocSites(ast),
		funcs:      collectFuncValues(ast),
		sharedVars: sharedVars,
		inProgress: map[*funcInfo]bool{},
		localCache: map[*js.BlockStmt]map[*js.Var]bool{},
		restSites:  numberRestSites(ast),
		results:    map[flowKey]Result{},
	}
	roots := a.discoverReachableRoots(ast)
	eventVars := map[*js.Var]bool{}
	for _, r := range roots {
		if r.eventVar != nil {
			eventVars[r.eventVar] = true
		}
	}
	a.sources, a.display = numberSources(ast, eventVars)

	a.analyzeReachable(ast, roots)
	if a.err != nil {
		return nil, 0, false, a.err
	}
	results, total, truncated := a.finalizeResults()
	return results, total, truncated, nil
}

// analyzeReachable runs the top level once, then every reachable callback root to
// a fixed point over the file-scope may-state that callbacks publish to and read
// from one another.
func (a *analysis) analyzeReachable(ast *js.AST, roots []rootSite) {
	// The top level runs once with a clean published state, so a request that runs
	// before any event cannot observe a taint a later handler produces.
	top := newState()
	top = a.analyzeBlock(&ast.BlockStmt, top)
	if !a.alive() {
		return
	}
	global := a.sharedState(top)
	// A socket that survives to file-scope state can be observed open by a later
	// callback, which is when a send on it becomes a network sink.
	markSocketsObservable(global)

	for a.alive() {
		changed := false
		for i := range roots {
			st := global.clone()
			a.suspensions = make([]*state, 0)
			a.bindRootParams(roots[i], st)
			a.returnExits = append(a.returnExits, nil)
			st = a.analyzeBlock(roots[i].fn.body, st)
			exits := a.popReturnExits(st)
			if !a.alive() {
				return
			}
			next := global
			for _, exit := range exits {
				next = a.publishShared(next, exit.state)
			}
			for _, suspended := range a.suspensions {
				next = a.publishShared(next, suspended)
			}
			a.suspensions = nil
			markSocketsObservable(next)
			if !stateEqual(next, global) {
				global = next
				changed = true
			}
		}
		if !changed || !a.fact() {
			return
		}
	}
}

// popReturnExits closes the current function-flow frame. Explicit return states
// and the normal fallthrough state are separate execution alternatives; code
// after a return must not inherit writes from the returned path.
func (a *analysis) popReturnExits(normalExit *state) []functionExit {
	index := len(a.returnExits) - 1
	exits := a.returnExits[index]
	a.returnExits = a.returnExits[:index]
	if normalExit.continues {
		exits = append(exits, functionExit{state: normalExit})
	}
	return exits
}

// bindRootParams binds a callback's parameters before its body. A keyboard
// handler's first parameter is the event object whose keystroke reads are the
// numbered sources, so only its later parameters are bound here.
func (a *analysis) bindRootParams(r rootSite, st *state) {
	start := 0
	if r.eventVar != nil {
		start = 1
	}
	for i := start; i < len(r.fn.params.List); i++ {
		if i < r.argCount {
			a.bindParamPattern(r.fn.params.List[i].Binding, value{}, st)
			continue
		}
		a.analyzeBinding(&r.fn.params.List[i], st, true)
	}
}

// sortedResults returns the recorded flows in deterministic content order.
func (a *analysis) sortedResults() []Result {
	out := make([]Result, 0, len(a.results))
	for _, r := range a.results {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return lessResult(out[i], out[j]) })
	return out
}

func lessResult(x, y Result) bool {
	if x.Source != y.Source {
		return x.Source < y.Source
	}
	xv, yv := joinChain(x.Via), joinChain(y.Via)
	if xv != yv {
		return xv < yv
	}
	return x.Sink < y.Sink
}

func joinChain(c []string) string {
	out := ""
	for i, s := range c {
		if i != 0 {
			out += "\x00"
		}
		out += s
	}
	return out
}

// record inserts a source-to-sink flow, keeping the shortest via chain when a
// route to the same endpoints already exists. Ties break lexicographically by
// the joined via names so output does not depend on map iteration order.
func (a *analysis) record(ts taintSet, sink js.INode, arg int, sinkText string) {
	for fact, chain := range ts {
		if !a.alive() {
			return
		}
		key := flowKey{source: fact.source, sink: sink, arg: arg, kind: sinkText}
		cand := Result{Source: a.display[fact.source], Via: append([]string(nil), chain...), Sink: sinkText}
		if ex, ok := a.results[key]; ok {
			if shorterChain(cand.Via, ex.Via) {
				a.results[key] = cand
			}
			continue
		}
		if !a.fact() {
			return
		}
		a.results[key] = cand
	}
}

func shorterChain(cand, existing []string) bool {
	if len(cand) != len(existing) {
		return len(cand) < len(existing)
	}
	return joinChain(cand) < joinChain(existing)
}

func (a *analysis) fact() bool {
	if a.err != nil {
		return false
	}
	if err := a.budget.addFact(); err != nil {
		a.err = err
		return false
	}
	return true
}

func (a *analysis) alive() bool {
	if a.err != nil {
		return false
	}
	if err := a.ctx.Err(); err != nil {
		a.err = err
		return false
	}
	return true
}

// numberSources assigns a deterministic occurrence id to every keyboard-source
// read whose base resolves to a discovered event variable. The traversal order
// does not affect output because results are content-sorted; it only needs to be
// stable across identical inputs.
func numberSources(ast *js.AST, eventVars map[*js.Var]bool) (map[js.IExpr]sourceOccurrence, map[int]string) {
	n := &sourceNumberer{eventVars: eventVars, out: map[js.IExpr]sourceOccurrence{}, display: map[int]string{}}
	js.Walk(n, ast)
	return n.out, n.display
}

type sourceNumberer struct {
	eventVars map[*js.Var]bool
	out       map[js.IExpr]sourceOccurrence
	display   map[int]string
	next      int
}

func (n *sourceNumberer) Exit(js.INode) {}

func (n *sourceNumberer) Enter(node js.INode) js.IVisitor {
	if walkComputedClassName(n, node) {
		return n
	}
	expr, ok := node.(js.IExpr)
	if !ok {
		return n
	}
	name, base, ok := memberAccessBytes(expr)
	if !ok || !isKeyboardProp(name) || !n.resolves(base) {
		return n
	}
	disp := memberDisplay(expr)
	n.out[expr] = sourceOccurrence{id: n.next, display: disp}
	n.display[n.next] = disp
	n.next++
	return n
}

func (n *sourceNumberer) resolves(base js.IExpr) bool {
	v := eventBaseVar(base)
	return v != nil && n.eventVars[v]
}

// mergeTaint unions two taint sets, keeping the shortest chain per source.
func mergeTaint(a, b taintSet) taintSet {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	out := make(taintSet, len(a)+len(b))
	for fact, ch := range a {
		out[fact] = ch
	}
	for fact, ch := range b {
		if ex, ok := out[fact]; !ok || shorterChain(ch, ex) {
			out[fact] = ch
		}
	}
	return out
}

// appendVia extends every chain in ts with name, skipping a redundant repeat so
// loop fixed points do not grow chains without bound.
func appendVia(ts taintSet, name string) taintSet {
	if len(ts) == 0 {
		return nil
	}
	out := make(taintSet, len(ts))
	for fact, ch := range ts {
		if len(ch) > 0 && ch[len(ch)-1] == name {
			out[fact] = ch
			continue
		}
		nc := make(taintChain, len(ch)+1)
		copy(nc, ch)
		nc[len(ch)] = name
		out[fact] = nc
	}
	return out
}

func taintEqual(a, b taintSet) bool {
	if len(a) != len(b) {
		return false
	}
	for fact, ca := range a {
		cb, ok := b[fact]
		if !ok || !chainEqual(ca, cb) {
			return false
		}
	}
	return true
}

func chainEqual(a, b taintChain) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
