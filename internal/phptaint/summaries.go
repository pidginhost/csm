package phptaint

import (
	"context"
	"errors"
	"sort"
	"sync/atomic"

	"github.com/VKCOM/php-parser/pkg/ast"
)

// precisionLossMarkers name calls that defeat static variable identity.
// extract() and compact() move values between named variables and an array
// at runtime; call_user_func(_array) dispatches through a value rather than
// a lexical name. Their presence is recorded so a caller knows coverage was
// reduced, rather than the loss passing silently.
var precisionLossMarkers = map[string]string{
	"extract":              "extract",
	"compact":              "compact",
	"call_user_func":       "dynamic-call",
	"call_user_func_array": "dynamic-call",
}

var errSummaryLimit = errors.New("too many function summaries to analyze")

type bodyKind uint8

const (
	bodyFunction bodyKind = iota
	bodyMethod
)

// summaryKey names one entry in a summaryTables namespace: which of the two
// tables it lives in, plus the bare name within that table.
type summaryKey struct {
	kind bodyKind
	name string
}

// callSiteSummaryKey reports the summaryKey a call site would resolve
// against, mirroring the node-type switch summaryTables.lookup uses. A call
// shape outside the three kinds facts.go records resolves to nothing, same
// as lookup itself.
func callSiteSummaryKey(call callSite) (summaryKey, bool) {
	switch call.node.(type) {
	case *ast.ExprFunctionCall:
		return summaryKey{kind: bodyFunction, name: call.name}, true
	case *ast.ExprMethodCall, *ast.ExprNullsafeMethodCall, *ast.ExprStaticCall:
		return summaryKey{kind: bodyMethod, name: call.name}, true
	}
	return summaryKey{}, false
}

// summaryBodyEvals counts how many times the interprocedural worklist below
// actually re-evaluated a body (taintedLocals plus its return expressions),
// as opposed to a body sitting untouched in the queue. It exists so a
// same-package white-box test can observe that this count grows with the
// call graph's edge count, not with (declaration count) x (declaration
// count), which is the structural invariant a dependency worklist is
// supposed to buy over a round-robin sweep. Nothing in this package branches
// on its value, so this is test-only observation, not shared process state.
var summaryBodyEvals atomic.Int64

// funcBody pairs a summarizable function or method with its collected facts
// and which summary namespace its name belongs to. Facts are collected once
// up front: they do not change across fixpoint rounds, only the summary
// tables consulted while interpreting them do.
type funcBody struct {
	name  string
	kind  bodyKind
	facts *scopeFacts
	// calls is the whole-file resolved-call view, kept so each evaluation can
	// re-collect the return expressions with namespace-level aliases intact.
	calls resolvedCallIndex
	// returnKeys names the summaries reachable from this body's return
	// expressions. Only the KEYS are kept, never the collected facts: a
	// return expression is collected without excluding nested declarations,
	// so for a body whose return lexically contains further declarations
	// those facts cover the whole remaining subtree, and retaining one per
	// body across the fixpoint is quadratic in nesting depth. Attacker-
	// written input reaches a gigabyte of live heap that way for a few
	// hundred KB of source. The keys are a few bytes each and are all the
	// dependency edges need.
	returnKeys []summaryKey
}

// dependencyKeys names every summary a single evaluation of this body can
// read: those reachable from its own statements, consulted while computing
// its local taint state, plus those reachable from each return expression,
// consulted while grading what it returns. The worklist's correctness rests
// on this being a SUPERSET of what an evaluation actually reads. If a body
// can read a summary it has no edge on, a later rise in that summary never
// wakes it, and the fixpoint's answer starts depending on the order bodies
// were queued in -- which is the order they were declared in, which an
// attacker writing the file chooses.
func (b funcBody) dependencyKeys() []summaryKey {
	keys := make([]summaryKey, 0, len(b.facts.callSites)+len(b.returnKeys))
	for _, call := range b.facts.callSites {
		if key, ok := callSiteSummaryKey(call); ok {
			keys = append(keys, key)
		}
	}
	return append(keys, b.returnKeys...)
}

// functionSummaries reports which user-defined functions and methods return
// remotely-sourced data, computed to a fixpoint over the call graph, plus any
// precision-loss markers observed while collecting their bodies.
//
// Functions and methods are kept in separate namespaces (summaryTables): PHP
// allows a function and a method, or methods on unrelated classes, to share
// a bare name, and a single shared table would let a tainted method
// anywhere in the file poison every same-named plain function call site. A
// method name declared by more than one class is dropped from the method
// table entirely rather than resolved to any one class's definition - a
// deliberate false-negative trade recorded as "ambiguous-method" precision
// loss, because this analyzer's zero-false-positive bar makes guessing
// wrong more expensive than a visible gap.
//
// This is what lets the analyzer see the motivating shape: a fetch in one
// function and a sink in another, joined only by a call. Without a summary
// for the fetching function, that flow is invisible to a single-scope pass.
func functionSummaries(ctx context.Context, f *scopeFacts) (summaryTables, []string, error) {
	bodies, loss, err := summaryBodies(ctx, f)
	if err != nil {
		return summaryTables{}, nil, err
	}
	tables, err := solveSummaries(ctx, bodies)
	if err != nil {
		return summaryTables{}, nil, err
	}
	names := make([]string, 0, len(loss))
	for name := range loss {
		names = append(names, name)
	}
	sort.Strings(names)
	if err := ctx.Err(); err != nil {
		return summaryTables{}, nil, err
	}
	return tables, names, nil
}

// summaryBodies collects every summarizable function and method body, with
// the precision loss observed while collecting them. Separated from the
// fixpoint below so the two can be exercised apart: a test can build the
// bodies for a file and then run its own reference fixpoint over them, which
// is what pins the worklist to the answer an exhaustive sweep would give.
func summaryBodies(ctx context.Context, f *scopeFacts) ([]funcBody, map[string]bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	loss := map[string]bool{}
	// The enclosing facts already cover every declaration body. Record loss
	// from them before omitting ambiguous methods, because that filter can
	// exclude the only body containing a precision-loss construct.
	recordPrecisionLoss(f, loss)

	// A single class cannot legally declare the same method name twice, so
	// any name appearing more than once in this flat, whole-file list was
	// declared by more than one class - ambiguous, without needing to track
	// which class owns which method. Ambiguous methods do not consume the
	// summary-body budget because they are deliberately omitted from the
	// summary table regardless of that budget.
	methodCounts := make(map[string]int, len(f.methods))
	for _, m := range f.methods {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		methodCounts[calleeName(m.Name)]++
	}
	summarizable := len(f.funcs)
	for _, count := range methodCounts {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if count > 1 {
			loss["ambiguous-method"] = true
			continue
		}
		summarizable++
	}
	if summarizable > maxSummarizedFuncs {
		return nil, nil, errSummaryLimit
	}

	// tree indexes every declaration in f (see declarationTree), so a
	// function or method nested inside another (however deeply, however
	// many if/while/switch/try/foreach wrappers it sits behind) is excluded
	// from its enclosing body's own facts by lookup rather than by
	// rescanning the file's declarations for every body, and so cannot
	// pollute that enclosing declaration's own interprocedural summary. In
	// production f is the same *scopeFacts analyze already indexed, so this
	// hits declarationTree's own cache rather than rebuilding, and is
	// already known to be within maxDeclarations here (analyze's cap check
	// runs first).
	tree := f.declarationTree()
	callIndex := newResolvedCallIndex(f)

	bodies := make([]funcBody, 0, summarizable)
	for _, fn := range f.funcs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		exclude := tree.exclusionFor(fn)
		facts := callIndex.apply(collectOwnStmts(fn.Stmts, &exclude))
		returnKeys, err := returnSummaryKeys(ctx, facts, callIndex)
		if err != nil {
			return nil, nil, err
		}
		bodies = append(bodies, funcBody{
			name: calleeName(fn.Name), kind: bodyFunction, facts: facts,
			calls: callIndex, returnKeys: returnKeys,
		})
	}

	for _, m := range f.methods {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		name := calleeName(m.Name)
		if methodCounts[name] > 1 {
			continue
		}
		// StmtClassMethod carries ONE Stmt vertex (normally a StmtStmtList),
		// unlike StmtFunction which carries a Stmts slice.
		exclude := tree.exclusionFor(m)
		facts := callIndex.apply(collectOwnStmts(methodStmts(m.Stmt), &exclude))
		returnKeys, err := returnSummaryKeys(ctx, facts, callIndex)
		if err != nil {
			return nil, nil, err
		}
		bodies = append(bodies, funcBody{
			name: name, kind: bodyMethod, facts: facts,
			calls: callIndex, returnKeys: returnKeys,
		})
	}
	// Recheck every included body using its independently collected facts.
	// The enclosing collection has one aggregate node budget, so it can stop
	// recording inside a declaration that was already discovered; the fresh
	// per-body budget can still preserve that declaration's loss markers.
	for _, b := range bodies {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		recordPrecisionLoss(b.facts, loss)
	}

	return bodies, loss, nil
}

// solveSummaries runs the interprocedural fixpoint over prebuilt bodies.
func solveSummaries(ctx context.Context, bodies []funcBody) (summaryTables, error) {
	// Summaries only ever move from absent to present, or to a higher
	// confidence, so this is a monotone fixpoint over a finite lattice
	// (three confidence levels) whose result does not depend on the order
	// bodies are (re)evaluated in - only on eventually evaluating every body
	// whose inputs changed since it was last evaluated. A body's inputs are
	// exactly the summaries of the functions and methods its own facts call,
	// so a worklist keyed on that call graph re-evaluates a body only when a
	// callee it actually references just changed, instead of re-sweeping
	// every body on every pass regardless of whether anything it depends on
	// moved. Which summaries a body depends on is exactly what
	// dependencyKeys reports, and that must stay a superset of what an
	// evaluation reads, or the order-independence claimed above is simply
	// false: edges drawn from a body's own statements alone miss a callee
	// invoked from inside a closure within a return, because a body's facts
	// exclude nested declarations while the collection used to grade its
	// return expression does not.
	//
	// This is the same dependency-worklist shape solveAssignments
	// already runs intraprocedurally in taint.go, applied one level up: a
	// body here plays the role an assignment plays there, and a produced
	// summary name plays the role a variable plays there. Termination
	// follows from the lattice being finite - at most one entry per body
	// name, each raised at most twice - rather than from any iteration
	// count, so it needs no cap sized to the input the way a round-robin
	// sweep would.
	produced := make(map[summaryKey]bool, len(bodies))
	for _, b := range bodies {
		if b.name == "" {
			continue
		}
		produced[summaryKey{kind: b.kind, name: b.name}] = true
	}

	// dependents maps a produced key to the bodies whose own facts call it,
	// i.e. the bodies to wake when that key's confidence rises. Built once
	// from each body's already-collected call sites, so this costs one pass
	// over the call sites this file already gathered rather than a rescan
	// per round.
	dependents := make(map[summaryKey][]int)
	queue := make([]int, 0, len(bodies))
	queued := make([]bool, len(bodies))
	for i, b := range bodies {
		if err := ctx.Err(); err != nil {
			return summaryTables{}, err
		}
		if b.name == "" {
			continue
		}
		for _, key := range b.dependencyKeys() {
			if !produced[key] {
				continue
			}
			dependents[key] = append(dependents[key], i)
		}
		queue = append(queue, i)
		queued[i] = true
	}
	enqueue := func(indices []int) {
		for _, i := range indices {
			if !queued[i] {
				queued[i] = true
				queue = append(queue, i)
			}
		}
	}

	tables := summaryTables{funcs: map[string]Confidence{}, methods: map[string]Confidence{}}
	for head := 0; head < len(queue); head++ {
		if err := ctx.Err(); err != nil {
			return summaryTables{}, err
		}
		i := queue[head]
		queued[i] = false
		b := bodies[i]

		best, found, err := evalBodySummary(ctx, b, tables)
		if err != nil {
			return summaryTables{}, err
		}
		if !found {
			continue
		}

		target := tables.funcs
		if b.kind == bodyMethod {
			target = tables.methods
		}
		if cur, ok := target[b.name]; ok && cur >= best {
			continue
		}
		target[b.name] = best
		enqueue(dependents[summaryKey{kind: b.kind, name: b.name}])
	}

	return tables, nil
}

// evalBodySummary grades what one body returns against the summaries known so
// far: Low..Certain plus whether anything tainted is returned at all. It reads
// only the summaries dependencyKeys reports, which is what lets the worklist
// wake exactly the bodies an update can affect.
func evalBodySummary(ctx context.Context, b funcBody, tables summaryTables) (Confidence, bool, error) {
	summaryBodyEvals.Add(1)
	st := taintedLocals(b.facts, tables)
	best := ConfidenceLow
	found := false
	for _, ret := range b.facts.returns {
		if err := ctx.Err(); err != nil {
			return ConfidenceLow, false, err
		}
		if ret.Expr == nil {
			continue
		}
		c, tainted := exprTaintFacts(b.calls.apply(collectScope(ret.Expr)), st, tables)
		if !tainted {
			continue
		}
		found = true
		if c > best {
			best = c
		}
	}
	return best, found, nil
}

// returnSummaryKeys names every summary reachable from a body's return
// expressions. calls is the whole-file resolved-call view, not an index
// rebuilt from f: f excludes nested declarations, while a return expression
// can read through an invoked closure or arrow function inside one. The
// whole-file view is what preserves namespace-level aliases for those nested
// calls.
//
// Each collection is transient. Only the keys survive, because the collected
// facts of a return expression cover every declaration nested inside it, and
// holding one per body for the life of the fixpoint costs memory quadratic in
// nesting depth on input an attacker writes.
func returnSummaryKeys(
	ctx context.Context, f *scopeFacts, calls resolvedCallIndex,
) ([]summaryKey, error) {
	var keys []summaryKey
	for _, ret := range f.returns {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if ret.Expr == nil {
			continue
		}
		for _, call := range calls.apply(collectScope(ret.Expr)).callSites {
			if key, ok := callSiteSummaryKey(call); ok {
				keys = append(keys, key)
			}
		}
	}
	return keys, nil
}

// recordPrecisionLoss folds one body's precision-loss facts into the running
// set. Variable-variables and dynamic calls are already flagged during
// collection (facts.go); this adds the calls whose names are known but whose
// effect on variable identity is not visible to the collector, such as
// extract() writing into caller-invisible names.
func recordPrecisionLoss(f *scopeFacts, loss map[string]bool) {
	for marker := range f.precisionLoss {
		loss[marker] = true
	}
	for name := range f.calls {
		if marker, ok := precisionLossMarkers[name]; ok {
			loss[marker] = true
		}
	}
}
