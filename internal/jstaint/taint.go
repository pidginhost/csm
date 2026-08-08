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

// taintSet maps a source occurrence id to the shortest via chain that carries
// that source's value to the current point. A nil or empty set is clean.
type taintSet map[int]taintChain

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

// analysis holds the mutable state for one Analyze call.
type analysis struct {
	ctx        context.Context
	budget     *resourceBudget
	sources    map[js.IExpr]sourceOccurrence
	sites      map[js.INode]int
	funcs      map[*js.Var][]*funcInfo
	sharedVars map[*js.Var]bool
	inProgress map[*funcInfo]bool
	retStack   []value
	display    map[int]string
	results    map[flowKey]Result
	loopDepth  int
	callDepth  int
	truncated  bool
	err        error
}

// taintPass is the production analysis pass wired into Analyze. It first enforces
// the structural depth, node, and cancellation limits with a bounded walk, then
// runs the taint analysis on the within-limit tree.
func taintPass(ctx context.Context, ast *js.AST, budget *resourceBudget) ([]Result, bool, error) {
	lv := &limitVisitor{ctx: ctx, budget: budget}
	js.Walk(lv, ast)
	if lv.err != nil {
		return nil, false, lv.err
	}

	handlers := discoverHandlers(ast)
	eventVars := map[*js.Var]bool{}
	for _, h := range handlers {
		if h.eventVar != nil {
			eventVars[h.eventVar] = true
		}
	}

	sources, display := numberSources(ast, eventVars)
	sharedVars := map[*js.Var]bool{}
	for _, v := range ast.Declared {
		sharedVars[canonicalVar(v)] = true
	}
	a := &analysis{
		ctx:        ctx,
		budget:     budget,
		sources:    sources,
		sites:      numberAllocSites(ast),
		funcs:      collectFuncValues(ast),
		sharedVars: sharedVars,
		inProgress: map[*funcInfo]bool{},
		display:    display,
		results:    map[flowKey]Result{},
	}

	a.analyzeReachable(ast)
	if a.err != nil {
		return nil, false, a.err
	}
	return a.sortedResults(), a.truncated, nil
}

// analyzeReachable runs the top level once, then every reachable callback root to
// a fixed point over the file-scope may-state that callbacks publish to and read
// from one another.
func (a *analysis) analyzeReachable(ast *js.AST) {
	roots := a.discoverReachableRoots(ast)

	// The top level runs once with a clean published state, so a request that runs
	// before any event cannot observe a taint a later handler produces.
	top := newState()
	a.analyzeBlock(&ast.BlockStmt, top)
	if !a.alive() {
		return
	}
	global := a.sharedState(top)

	for a.alive() {
		changed := false
		for i := range roots {
			st := global.clone()
			a.bindRootParams(roots[i], st)
			a.analyzeBlock(roots[i].fn.body, st)
			if !a.alive() {
				return
			}
			next := a.publishShared(global, st)
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

// bindRootParams binds a callback's parameters before its body. A keyboard
// handler's first parameter is the event object whose keystroke reads are the
// numbered sources, so only its later parameters are bound here.
func (a *analysis) bindRootParams(r rootSite, st *state) {
	start := 0
	if r.eventVar != nil {
		start = 1
	}
	for i := start; i < len(r.fn.params.List); i++ {
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
	for id, chain := range ts {
		if !a.alive() {
			return
		}
		key := flowKey{source: id, sink: sink, arg: arg, kind: sinkText}
		cand := Result{Source: a.display[id], Via: append([]string(nil), chain...), Sink: sinkText}
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
	for id, ch := range a {
		out[id] = ch
	}
	for id, ch := range b {
		if ex, ok := out[id]; !ok || shorterChain(ch, ex) {
			out[id] = ch
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
	for id, ch := range ts {
		if len(ch) > 0 && ch[len(ch)-1] == name {
			out[id] = ch
			continue
		}
		nc := make(taintChain, len(ch)+1)
		copy(nc, ch)
		nc[len(ch)] = name
		out[id] = nc
	}
	return out
}

func taintEqual(a, b taintSet) bool {
	if len(a) != len(b) {
		return false
	}
	for id, ca := range a {
		cb, ok := b[id]
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
