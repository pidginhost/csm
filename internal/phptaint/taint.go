package phptaint

import (
	"context"
	"sort"
	"strings"

	"github.com/VKCOM/php-parser/pkg/ast"
)

// decoders preserve taint and raise confidence: fetching plaintext and
// executing it has a small benign population, but fetching, decoding, then
// executing has effectively none.
var decoders = map[string]bool{
	"base64_decode": true, "gzinflate": true, "gzuncompress": true,
	"gzdecode": true, "str_rot13": true, "hex2bin": true,
	"convert_uudecode": true, "unserialize": true, "pack": true,
}

// There is no passthrough allowlist: taint propagation is structural, not
// name-based. exprTaint marks any expression tainted if it references a
// tainted variable anywhere in its subtree, so trim($a), sprintf($a), and an
// unlisted some_helper($a) are all already covered without naming a single
// one of them. A name list here could only ever be narrower than that rule.

// taintState maps a variable name to the strongest confidence with which it
// carries remote content.
type taintState map[string]Confidence

// summaryTables holds interprocedural summaries in two namespaces so a
// function and a method that happen to share a name can never collide: PHP
// resolves f(), $obj->f(), and Class::f() through distinct call syntax, and
// callSite.node retains which syntax was used, so a lookup can always pick
// the namespace the call site itself selects. A single shared map would let
// a tainted method anywhere in the file poison every same-named plain
// function call site, which is false-positive-only but unacceptable given
// this analyzer's zero-false-positive bar against real WordPress/plugin code.
type summaryTables struct {
	funcs   map[string]Confidence
	methods map[string]Confidence
}

// lookup resolves a call site's summary in the namespace its call syntax
// selects. A node shape outside the three call kinds facts.go records
// (should not occur) resolves to nothing rather than guessing a namespace.
func (s summaryTables) lookup(call callSite) (Confidence, bool) {
	switch call.node.(type) {
	case *ast.ExprFunctionCall:
		c, ok := s.funcs[call.name]
		return c, ok
	case *ast.ExprMethodCall, *ast.ExprNullsafeMethodCall, *ast.ExprStaticCall:
		c, ok := s.methods[call.name]
		return c, ok
	}
	return ConfidenceLow, false
}

func (s taintState) raise(name string, c Confidence) bool {
	if name == "" {
		return false
	}
	if cur, ok := s[name]; ok && cur >= c {
		return false
	}
	s[name] = c
	return true
}

type taintAssignment struct {
	target  string
	node    ast.Vertex
	rhs     nodeSpan
	origins []taintOrigin
}

type taintOrigin struct {
	variable   string
	assignment int
	confidence Confidence
	fixed      bool
	decoded    bool
}

type positionedOrigin struct {
	nodeSpan
	origin taintOrigin
	self   int
}

type assignmentInterval struct {
	nodeSpan
	assignment int
}

// taintedLocals computes the tainted variables of one scope to a fixpoint. It
// is flow-insensitive: assignment order within the scope is not modelled. A
// dependency worklist reaches arbitrarily long local chains without borrowing
// the interprocedural summary-round limit or silently returning a partial state.
func taintedLocals(f *scopeFacts, summaries summaryTables) taintState {
	assignments, ok := compileAssignments(f, summaries)
	if !ok {
		return taintedLocalsFallback(f, summaries)
	}
	return solveAssignments(assignments)
}

func compileAssignments(f *scopeFacts, summaries summaryTables) ([]taintAssignment, bool) {
	assignments := make([]taintAssignment, 0, len(f.assigns)+len(f.references)*2+len(f.concats))
	for _, a := range f.assigns {
		var ok bool
		assignments, _, ok = appendAssignment(assignments, a, a.Var, a.Expr)
		if !ok {
			return nil, false
		}
	}
	for _, a := range f.references {
		var ok bool
		assignments, _, ok = appendAssignment(assignments, a, a.Var, a.Expr)
		if !ok {
			return nil, false
		}
	}
	for _, a := range f.concats {
		var index int
		var ok bool
		assignments, index, ok = appendAssignment(assignments, a, a.Var, a.Expr)
		if !ok {
			return nil, false
		}
		if index >= 0 {
			assignments[index].origins = append(assignments[index].origins, taintOrigin{
				variable: assignedTargetKey(a.Var), assignment: -1,
			})
		}
	}

	forwardCount := len(assignments)
	positioned := make([]positionedOrigin, 0, len(f.varNodes)+len(f.callSites)+forwardCount)
	for _, variable := range f.readVarNodes() {
		span, ok := spanOf(variable.node)
		if !ok {
			return nil, false
		}
		positioned = append(positioned, positionedOrigin{
			nodeSpan: span,
			origin:   taintOrigin{variable: variable.name, assignment: -1},
			self:     -1,
		})
	}
	for _, call := range f.callNodes {
		if confidence, source := sourceConfidence(call); source {
			span, ok := spanOf(call)
			if !ok {
				return nil, false
			}
			positioned = append(positioned, positionedOrigin{
				nodeSpan: span,
				origin: taintOrigin{
					assignment: -1, confidence: confidence, fixed: true,
				},
				self: -1,
			})
		}
	}
	for _, call := range f.callSites {
		confidence, summarized := summaries.lookup(call)
		if !summarized {
			continue
		}
		span, ok := spanOf(call.node)
		if !ok {
			return nil, false
		}
		positioned = append(positioned, positionedOrigin{
			nodeSpan: span,
			origin: taintOrigin{
				assignment: -1, confidence: confidence, fixed: true,
			},
			self: -1,
		})
	}
	for i := 0; i < forwardCount; i++ {
		span, ok := spanOf(assignments[i].node)
		if !ok {
			return nil, false
		}
		positioned = append(positioned, positionedOrigin{
			nodeSpan: span,
			origin:   taintOrigin{assignment: i},
			self:     i,
		})
	}

	decoderSpans := make([]nodeSpan, 0)
	for _, call := range f.callNodes {
		if !decoders[calleeName(call.Function)] {
			continue
		}
		for _, input := range decoderInputs(call) {
			if span, ok := spanOf(input); ok {
				decoderSpans = append(decoderSpans, span)
			} else {
				return nil, false
			}
		}
	}
	decoders := newSpanIndex(decoderSpans)
	for i := range positioned {
		positioned[i].origin.decoded = decoders.contains(positioned[i].nodeSpan)
	}
	distributeOrigins(assignments, positioned)

	// PHP references alias both names. A later write through either side
	// changes the other, so add the persistent reverse dependency after the
	// concrete assignment expression has received its own RHS origins.
	for _, reference := range f.references {
		target := assignedTargetKey(reference.Expr)
		source := assignedTargetKey(reference.Var)
		if target == "" || source == "" {
			continue
		}
		assignments = append(assignments, taintAssignment{
			target: target,
			origins: []taintOrigin{{
				variable: source, assignment: -1,
			}},
		})
	}
	return assignments, true
}

func appendAssignment(assignments []taintAssignment, node, target, expr ast.Vertex) ([]taintAssignment, int, bool) {
	name := assignedTargetKey(target)
	if name == "" {
		return assignments, -1, true
	}
	rhs, ok := spanOf(expr)
	if !ok {
		return nil, -1, false
	}
	assignments = append(assignments, taintAssignment{target: name, node: node, rhs: rhs})
	return assignments, len(assignments) - 1, true
}

func distributeOrigins(assignments []taintAssignment, origins []positionedOrigin) {
	intervals := make([]assignmentInterval, 0, len(assignments))
	for i := range assignments {
		if assignments[i].node != nil {
			intervals = append(intervals, assignmentInterval{nodeSpan: assignments[i].rhs, assignment: i})
		}
	}
	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].start != intervals[j].start {
			return intervals[i].start < intervals[j].start
		}
		return intervals[i].end > intervals[j].end
	})
	sort.Slice(origins, func(i, j int) bool {
		if origins[i].start != origins[j].start {
			return origins[i].start < origins[j].start
		}
		return origins[i].end < origins[j].end
	})

	stack := make([]assignmentInterval, 0)
	next := 0
	for _, origin := range origins {
		for next < len(intervals) && intervals[next].start <= origin.start {
			interval := intervals[next]
			for len(stack) > 0 && stack[len(stack)-1].end < interval.start {
				stack = stack[:len(stack)-1]
			}
			stack = append(stack, interval)
			next++
		}
		for len(stack) > 0 && stack[len(stack)-1].end < origin.end {
			stack = stack[:len(stack)-1]
		}
		for i := len(stack) - 1; i >= 0; i-- {
			interval := stack[i]
			if interval.assignment == origin.self || interval.start > origin.start || interval.end < origin.end {
				continue
			}
			assignments[interval.assignment].origins = append(assignments[interval.assignment].origins, origin.origin)
			break
		}
	}
}

type spanIndex struct {
	spans   []nodeSpan
	maxEnds []int
}

func newSpanIndex(spans []nodeSpan) spanIndex {
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	index := spanIndex{spans: spans, maxEnds: make([]int, len(spans))}
	maxEnd := -1
	for i, span := range spans {
		if span.end > maxEnd {
			maxEnd = span.end
		}
		index.maxEnds[i] = maxEnd
	}
	return index
}

func (index spanIndex) contains(span nodeSpan) bool {
	i := sort.Search(len(index.spans), func(i int) bool { return index.spans[i].start > span.start }) - 1
	return i >= 0 && index.maxEnds[i] >= span.end
}

func solveAssignments(assignments []taintAssignment) taintState {
	st := taintState{}
	variableDependents := make(map[string][]int)
	assignmentDependents := make([][]int, len(assignments))
	for i, assignment := range assignments {
		for _, origin := range assignment.origins {
			switch {
			case origin.fixed:
			case origin.assignment >= 0:
				assignmentDependents[origin.assignment] = append(assignmentDependents[origin.assignment], i)
			case origin.variable != "":
				variableDependents[origin.variable] = append(variableDependents[origin.variable], i)
			}
		}
	}

	queue := make([]int, len(assignments))
	queued := make([]bool, len(assignments))
	outputs := make([]Confidence, len(assignments))
	outputSet := make([]bool, len(assignments))
	for i := range assignments {
		queue[i] = i
		queued[i] = true
	}
	enqueue := func(indices []int) {
		for _, index := range indices {
			if !queued[index] {
				queued[index] = true
				queue = append(queue, index)
			}
		}
	}

	for head := 0; head < len(queue); head++ {
		i := queue[head]
		queued[i] = false
		best := ConfidenceLow
		found := false
		decoded := false
		for _, origin := range assignments[i].origins {
			var confidence Confidence
			var active bool
			switch {
			case origin.fixed:
				confidence, active = origin.confidence, true
			case origin.assignment >= 0:
				confidence, active = outputs[origin.assignment], outputSet[origin.assignment]
			default:
				confidence, active = st[origin.variable]
			}
			if !active {
				continue
			}
			found = true
			decoded = decoded || origin.decoded
			if confidence > best {
				best = confidence
			}
		}
		if !found {
			continue
		}
		if decoded {
			best = ConfidenceCertain
		}
		if outputSet[i] && outputs[i] >= best {
			continue
		}
		outputs[i], outputSet[i] = best, true
		enqueue(assignmentDependents[i])
		if st.raise(assignments[i].target, best) {
			enqueue(variableDependents[assignments[i].target])
		}
	}
	return st
}

// taintedLocalsFallback is the oracle path: no compiled solver, just direct
// fixpoint iteration over the raw facts. Its round cap must terminate AND
// stay complete. A fixed cap (the original defect) is neither: a reverse-
// ordered assignment chain propagates taint exactly one hop per round, so a
// chain longer than the cap evades detection entirely. Capping at the number
// of assignment facts plus one is always enough, because no dependency chain
// in this scope can have more hops than this scope has assignments, and it
// still terminates because it is a fixed bound.
func taintedLocalsFallback(f *scopeFacts, summaries summaryTables) taintState {
	st := taintState{}
	maxRounds := len(f.assigns) + len(f.references) + len(f.concats) + 1
	for round := 0; round < maxRounds; round++ {
		changed := false
		for _, assignment := range f.assigns {
			if confidence, tainted := exprTaint(assignment.Expr, st, summaries); tainted {
				changed = st.raise(assignedTargetKey(assignment.Var), confidence) || changed
			}
		}
		for _, assignment := range f.references {
			if confidence, tainted := exprTaint(assignment.Expr, st, summaries); tainted {
				changed = st.raise(assignedTargetKey(assignment.Var), confidence) || changed
			}
			if confidence, tainted := exprTaint(assignment.Var, st, summaries); tainted {
				changed = st.raise(assignedTargetKey(assignment.Expr), confidence) || changed
			}
		}
		for _, assignment := range f.concats {
			if confidence, tainted := exprTaint(assignment.Expr, st, summaries); tainted {
				changed = st.raise(assignedTargetKey(assignment.Var), confidence) || changed
			}
		}
		if !changed {
			return st
		}
	}
	return st
}

// assignedVarName returns the root local variable written by an assignment,
// flattening any array-element or property-fetch chain onto its base
// variable. This remains the array-element behavior (the spec permits
// over-approximating containers, and array keys are not tracked at all), and
// it is also assignedTargetKey's fallback for a property chain it cannot key
// more precisely -- see there for when that applies.
func assignedVarName(target ast.Vertex) string {
	for target != nil {
		switch n := target.(type) {
		case *ast.ExprVariable:
			return varName(n.Name)
		case *ast.ExprArrayDimFetch:
			target = n.Var
		case *ast.ExprPropertyFetch:
			target = n.Var
		default:
			return ""
		}
	}
	return ""
}

// propertyFetchParts returns the base expression and the (possibly dynamic)
// property vertex of a property fetch, regardless of whether it used the
// regular ("->") or nullsafe ("?->") operator. Nullsafe fetches cannot
// appear as an assignment target in valid PHP, but a property that was
// WRITTEN through the regular operator must still be found by a later READ
// spelled with "?->", so both node types resolve through the one path
// assignedTargetKey uses for both directions.
func propertyFetchParts(n ast.Vertex) (base, prop ast.Vertex, ok bool) {
	switch v := n.(type) {
	case *ast.ExprPropertyFetch:
		return v.Var, v.Prop, true
	case *ast.ExprNullsafePropertyFetch:
		return v.Var, v.Prop, true
	}
	return nil, nil, false
}

// assignedTargetKey returns the taint-state key an assignment target -- or,
// via readVarNodes, a later read of the identical expression shape --
// resolves to. A bare variable resolves to its own name.
//
// The WHOLE access chain is walked, in whatever order property fetches
// ("->"/"?->") and array-dim fetches ("[...]") appear and however deeply
// nested: each property fetch contributes its name to the compound key, and
// each array-dim fetch is transparent, unwrapped without contributing a
// segment of its own. That is what keeps array indices over-approximated
// (the spec permits over-approximating containers: $a->log[] = X and
// $a->log[3] = Y both key to "a->log" as a whole -- array keys are not
// tracked) while still scoping precisely to the property chain around them.
//
// This generality is load-bearing, not incidental: an earlier version
// only unwrapped property fetches, so an array-dim fetch sitting
// OUTERMOST over a property fetch ($this->log[] = <tainted>, one of the
// most common idioms in OO PHP -- logs, queues, error collections, caches)
// broke the walk immediately and fell back to the bare base variable,
// reintroducing the exact wholesale-$this false-positive class this key
// scoping exists to close. Handling only that one shape and stopping would
// leave the same gap for every other ordering ($a[0]->b, $a->b[0]->c[1],
// ...), so the loop below handles both access kinds generically, in any
// order, rather than adding a case for the reported shape and calling it
// done.
//
// A property fetch is different from a bare variable or array element:
// $this->body = <tainted> must NOT taint every later use of bare $this,
// because $this appears in nearly every method of a class and one tainted
// property would otherwise poison every sink in it. This is deliberately
// not special-cased to the name "$this": $obj->prop = <tainted> gets
// exactly the same treatment. The key scopes to
// the full static property path (so $this->a->b is distinct from both
// $this->a and $this->a->c), joining base and property names with "->", a
// sequence no PHP variable name can contain, so a compound key can never
// collide with a bare one.
//
// The walk is iterative, not recursive: an access chain's depth is
// attacker-controlled PHP source ($a->b->c->... or $a[0][0][0]...), and Go
// recursion over unbounded attacker-controlled depth is an unrecoverable
// stack overflow, the same hazard TestTaintHandlesDeeplyNestedAssignments
// guards elsewhere in this package.
//
// A property whose name is not statically known ($obj->$name = X) has no
// specific key to scope to, so the ENTIRE chain falls back to
// assignedVarName's base-variable over-approximation, rather than a
// partially-keyed name nothing else would ever match.
func assignedTargetKey(target ast.Vertex) string {
	var props []string
	node := target
	for {
		if base, prop, ok := propertyFetchParts(node); ok {
			name := calleeName(prop)
			if name == "" {
				return assignedVarName(target)
			}
			props = append(props, name)
			node = base
			continue
		}
		if dim, ok := node.(*ast.ExprArrayDimFetch); ok {
			node = dim.Var
			continue
		}
		break
	}
	base := assignedVarName(node)
	if base == "" || len(props) == 0 {
		return base
	}
	for i, j := 0, len(props)-1; i < j; i, j = i+1, j-1 {
		props[i], props[j] = props[j], props[i]
	}
	return base + "->" + strings.Join(props, "->")
}

// exprTaint reports whether an expression carries remote content, and with
// what confidence. It collects the subtree once and correlates decoder inputs
// by source positions, without recursing over the parsed structure.
func exprTaint(e ast.Vertex, st taintState, summaries summaryTables) (Confidence, bool) {
	if e == nil {
		return ConfidenceLow, false
	}
	return exprTaintFacts(collectScope(e), st, summaries)
}

func exprTaintFacts(sub *scopeFacts, st taintState, summaries summaryTables) (Confidence, bool) {
	best, found, origins := activeTaint(sub, st, summaries)
	if !found {
		return ConfidenceLow, false
	}
	// A decoder raises confidence to Certain only when the tainted value
	// passed through THAT decoder's own argument, not merely somewhere else
	// in the same expression: f(base64_decode($clean), $tainted) must stay
	// at the source's own grade, because the decode never touched $tainted.
	decoderSpans := make([]nodeSpan, 0)
	for _, call := range sub.callNodes {
		if !decoders[calleeName(call.Function)] {
			continue
		}
		for _, input := range decoderInputs(call) {
			if span, ok := spanOf(input); ok {
				decoderSpans = append(decoderSpans, span)
			}
		}
	}
	decoderIndex := newSpanIndex(decoderSpans)
	for _, origin := range origins {
		if decoderIndex.contains(origin) {
			return ConfidenceCertain, true
		}
	}
	return best, true
}

// decoderInputs returns only arguments that carry data through the decoder.
// Most decoder APIs consume their payload in argument zero. pack is the
// exception: argument zero is a format string and the values begin at one.
func decoderInputs(call *ast.ExprFunctionCall) []ast.Vertex {
	start := 0
	if calleeName(call.Function) == "pack" {
		start = 1
	}
	if start >= len(call.Args) {
		return nil
	}
	inputs := make([]ast.Vertex, 0, len(call.Args)-start)
	end := start + 1
	if start == 1 {
		end = len(call.Args)
	}
	for _, argNode := range call.Args[start:end] {
		if arg, ok := argNode.(*ast.Argument); ok {
			inputs = append(inputs, arg.Expr)
		}
	}
	return inputs
}

// flowResult retains whether its already-bounded display evidence was
// shortened. Keeping this beside the Result until deduplication is complete
// lets Analyze report truncation only for evidence that actually survives to
// the returned result slice.
type flowResult struct {
	Result
	evidenceTruncated bool
}

// capturableNames expands a scope's taint keys into the binding names a
// capture can actually spell. Taint on a property is keyed by its whole access
// path ("o->body"), but a closure captures the base variable ($o) and receives
// the property along with it, so the base name has to be markable too or a
// genuinely dropped capture is never recorded.
func capturableNames(st taintState) map[string]bool {
	names := make(map[string]bool, len(st))
	for key := range st {
		names[key] = true
		if base, _, found := strings.Cut(key, "->"); found {
			names[base] = true
		}
	}
	return names
}

// hasDroppedCapture reports whether any closure or arrow function receives an
// outer binding that was tainted in the scope it captured from.
//
// A closure's body is analysed as its own scope, which is what stops an
// unrelated same-named outer variable from firing on clean code. The cost is
// that a value the closure genuinely does receive through use(), or that an
// arrow function picks up implicitly, stops being tracked at the boundary.
// This package's contract is that a reduction in coverage is recorded rather
// than passed over, so the drop is reported as precision loss.
//
// The check is deliberately gated on the captured value ACTUALLY being
// tainted. Capturing is ordinary PHP and appears in roughly one in seven of
// the files this analyzer examines, so a marker raised on the shape alone
// would be noise an operator cannot act on. Gated this way it means exactly
// one thing: taint was dropped here.
//
// Enclosing states are computed lazily and memoised, so a file with no
// capturing closure pays nothing and a scope with several capturing children
// is solved once. Nothing is seeded INTO a closure: taint deliberately does
// not cross the boundary, it is only reported as lost.
func hasDroppedCapture(
	ctx context.Context, all *scopeFacts, tree declTree,
	factsByScope map[ast.Vertex]*scopeFacts, summaries summaryTables,
) (bool, error) {
	if len(all.closures) == 0 && len(all.arrowFuncs) == 0 {
		return false, nil
	}

	// Record only declarations that actually capture a name. Building this
	// cheap structural index first preserves the important lazy path: a file
	// containing only non-capturing declarations never solves another taint
	// state merely to decide that there was no capture.
	captures := make(map[ast.Vertex]map[string]bool)
	for _, cl := range all.closures {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		names := closureCaptureNames(cl)
		// A non-static closure created in object context binds $this
		// implicitly, so it appears in no use() clause while still carrying
		// whatever the enclosing object holds.
		if body := factsByScope[cl]; cl.StaticTkn == nil && body != nil && body.vars["this"] {
			names["this"] = true
		}
		if len(names) > 0 {
			captures[cl] = names
		}
	}
	for _, af := range all.arrowFuncs {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		body := factsByScope[af]
		if body == nil {
			continue
		}
		if names := arrowCaptureNames(af, body); len(names) > 0 {
			captures[af] = names
		}
	}

	// $this is the exception to an ordinary closure being a hard capture
	// boundary. Every non-static closure created in object context is bound to
	// that object, even when only a declaration nested inside the closure reads
	// $this. The independently collected closure facts exclude that nested
	// declaration, so surface the implicit capture on every non-static
	// closure/arrow along the path. Static declarations and named lexical
	// scopes remain hard boundaries. Stopping at an already surfaced node keeps
	// the total walk linear when many captures share a deeply nested path.
	thisForwarded := make(map[ast.Vertex]bool)
	var thisSeeds []ast.Vertex
	for node, names := range captures {
		if names["this"] {
			thisSeeds = append(thisSeeds, node)
		}
	}
	for _, node := range thisSeeds {
		for scope := tree.parent[node]; scope != nil && !thisForwarded[scope]; scope = tree.parent[scope] {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			forwards := false
			switch declaration := scope.(type) {
			case *ast.ExprClosure:
				forwards = declaration.StaticTkn == nil
			case *ast.ExprArrowFunction:
				forwards = declaration.StaticTkn == nil
			}
			if !forwards {
				break
			}
			thisForwarded[scope] = true
			names := captures[scope]
			if names == nil {
				names = map[string]bool{}
				captures[scope] = names
			}
			names["this"] = true
		}
	}
	if len(captures) == 0 {
		return false, nil
	}

	// A capture nested directly in an arrow function also makes that arrow
	// capture the same binding implicitly. Mark every enclosing arrow on a
	// capture path, plus the first ordinary lexical scope that supplies the
	// value. Stopping when an already-marked scope is reached makes the total
	// walk linear in declaration count even for deeply nested arrow trees.
	needed := make(map[ast.Vertex]bool, len(captures)+1)
	for node := range captures {
		scope := tree.parent[node]
		for !needed[scope] {
			needed[scope] = true
			if _, arrow := scope.(*ast.ExprArrowFunction); !arrow {
				break
			}
			scope = tree.parent[scope]
		}
	}

	// Taint states remain lazy and are memoised by their lexical scope. A
	// class body can enclose a declaration but has no local variable facts of
	// its own, so its state is intentionally empty.
	states := make(map[ast.Vertex]taintState, len(needed))
	stateFor := func(scope ast.Vertex) (taintState, error) {
		if st, solved := states[scope]; solved {
			return st, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var st taintState
		if f := factsByScope[scope]; f != nil {
			st = taintedLocals(f, summaries)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		states[scope] = st
		return st, nil
	}

	// active is a marker-only view of which tainted bindings are available at
	// the current declaration boundary. It is never passed to taintedLocals or
	// findFlows and therefore never seeds a closure or arrow body. Arrow scopes
	// inherit the view because PHP propagates captures through nested arrows;
	// every other declaration starts a new lexical variable scope. Boundary
	// IDs make those resets O(1), while per-name stacks make enter/leave O(1).
	type binding struct {
		boundary int
		tainted  bool
	}
	type frame struct {
		end              int
		previousBoundary int
		pushed           []string
	}
	active := make(map[string][]binding)
	boundary, nextBoundary := 0, 0
	push := func(name string, tainted bool, pushed *[]string) {
		active[name] = append(active[name], binding{boundary: boundary, tainted: tainted})
		*pushed = append(*pushed, name)
	}
	pop := func(f frame) {
		for i := len(f.pushed) - 1; i >= 0; i-- {
			name := f.pushed[i]
			stack := active[name]
			if len(stack) == 1 {
				delete(active, name)
			} else {
				active[name] = stack[:len(stack)-1]
			}
		}
		boundary = f.previousBoundary
	}
	capturesActive := func(names map[string]bool) bool {
		for name := range names {
			stack := active[name]
			if len(stack) == 0 {
				continue
			}
			value := stack[len(stack)-1]
			if value.boundary == boundary && value.tainted {
				return true
			}
		}
		return false
	}

	if needed[nil] {
		st, err := stateFor(nil)
		if err != nil {
			return false, err
		}
		for name := range capturableNames(st) {
			active[name] = []binding{{boundary: boundary, tainted: true}}
		}
	}

	frames := make([]frame, 0, 8)
	seen := make(map[ast.Vertex]bool, len(captures))
	for _, declaration := range tree.ordered {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		// Exclusive end position, matching declarationTree's sweep: a
		// declaration starting exactly where a frame ends is outside it.
		for len(frames) > 0 && frames[len(frames)-1].end <= declaration.start {
			pop(frames[len(frames)-1])
			frames = frames[:len(frames)-1]
		}

		if names := captures[declaration.node]; len(names) > 0 {
			seen[declaration.node] = true
			if capturesActive(names) {
				if err := ctx.Err(); err != nil {
					return false, err
				}
				return true, nil
			}
		}

		f := frame{end: declaration.end, previousBoundary: boundary}
		if needed[declaration.node] {
			if af, arrow := declaration.node.(*ast.ExprArrowFunction); arrow {
				// A static arrow still captures ordinary outer variables, but
				// it neither receives $this nor forwards it to a declaration
				// nested inside the arrow.
				if af.StaticTkn != nil {
					push("this", false, &f.pushed)
				}
				// Parameters are the arrow's own bindings and shadow an
				// identically named capture from any enclosing scope.
				for name := range paramNames(af.Params) {
					push(name, false, &f.pushed)
				}
			} else {
				nextBoundary++
				boundary = nextBoundary
			}
			st, err := stateFor(declaration.node)
			if err != nil {
				return false, err
			}
			for name := range capturableNames(st) {
				push(name, true, &f.pushed)
			}
		}
		frames = append(frames, f)
	}

	// Parser-produced declaration nodes always carry positions and therefore
	// appear in tree.ordered. Retain the conservative direct-scope behavior if
	// a future parser version emits an unpositioned capture node.
	for node, names := range captures {
		if seen[node] {
			continue
		}
		st, err := stateFor(tree.parent[node])
		if err != nil {
			return false, err
		}
		available := capturableNames(st)
		for name := range names {
			if available[name] {
				return true, nil
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return false, nil
}

// unresolvableAssignRHS returns the right-hand-side expression of every
// assignment (=, =&, .=) in f whose target assignedTargetKey cannot resolve
// to a taint-state key: a method-call result mid-chain (`$a->b()->c = X`),
// a static property (`Foo::$cache = X`), a list()/[] destructuring target,
// or a variable-variable base. This is a purely structural scan (no taint
// fixpoint), used to cheaply decide whether hasUnresolvableTaintedTarget
// needs to do any further work at all.
func unresolvableAssignRHS(ctx context.Context, f *scopeFacts) ([]ast.Vertex, error) {
	var out []ast.Vertex
	for _, a := range f.assigns {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if assignedTargetKey(a.Var) == "" {
			out = append(out, a.Expr)
		}
	}
	for _, a := range f.references {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if assignedTargetKey(a.Var) == "" {
			out = append(out, a.Expr)
		}
	}
	for _, a := range f.concats {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if assignedTargetKey(a.Var) == "" {
			out = append(out, a.Expr)
		}
	}
	return out, nil
}

// hasUnresolvableTaintedTarget reports whether f contains an assignment
// whose target cannot be keyed (see unresolvableAssignRHS) AND whose
// right-hand side is actually tainted -- the only case that represents a
// real, silent loss of tracking. `list($a, $b) = ['x', 'y']` and
// `Foo::$cache = 'literal'` drop nothing at all and must not be flagged;
// `list($a, $b) = curl_exec($u)` and `Foo::$cache = curl_exec($u)`
// genuinely drop taint this package cannot track further and must be.
//
// An earlier version of this check fired on the unkeyable SHAPE alone,
// regardless of taint. Measured against the reference corpus that reported
// the marker on 38.75% of analyzed files -- overwhelmingly ordinary,
// completely benign idioms (list() destructuring, static properties used
// as singletons/caches) that were not dropping anything -- noise no
// operator could act on. Gating on the RHS's own taint is what makes the
// marker mean "we dropped taint here" instead of "this file uses PHP".
//
// f.assigns/f.references/f.concats are scanned for an unresolvable target
// FIRST (see unresolvableAssignRHS), before the per-scope taint fixpoint
// below runs at all, so the (relatively expensive) taintedLocals call is
// skipped entirely for the overwhelming majority of scopes that have no
// unresolvable target -- the same early-return findFlows already uses for
// f.sinks being empty. Active origins are then correlated against the RHS
// spans from f's existing facts. Besides avoiding a traversal per RHS, this
// preserves canonical names already resolved from `use function` aliases;
// recollecting an isolated RHS has no access to the enclosing alias imports.
func hasUnresolvableTaintedTarget(
	ctx context.Context, f *scopeFacts, summaries summaryTables,
) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	rhs, err := unresolvableAssignRHS(ctx, f)
	if err != nil {
		return false, err
	}
	if len(rhs) == 0 {
		return false, nil
	}

	rhsSpans := make([]nodeSpan, 0, len(rhs))
	var unpositioned []ast.Vertex
	for _, expr := range rhs {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if span, ok := spanOf(expr); ok {
			rhsSpans = append(rhsSpans, span)
		} else {
			unpositioned = append(unpositioned, expr)
		}
	}

	var rhsReads []namedNodeSpan
	if len(rhsSpans) > 0 {
		index := newSpanIndex(rhsSpans)
		for _, call := range f.callNodes {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			span, positioned := spanOf(call)
			if positioned && index.contains(span) {
				if _, source := sourceConfidence(call); source {
					return true, nil
				}
			}
		}
		for _, call := range f.callSites {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			span, positioned := spanOf(call.node)
			if positioned && index.contains(span) {
				if _, summarized := summaries.lookup(call); summarized {
					return true, nil
				}
			}
		}
		for _, variable := range f.readVarNodes() {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			span, positioned := spanOf(variable.node)
			if positioned && index.contains(span) {
				rhsReads = append(rhsReads, variable)
			}
		}
	}

	// Literal RHS values and direct source/summary calls are already decided
	// above. Only variable-carried taint (or a synthetic positionless AST)
	// needs the full per-scope assignment fixpoint.
	if len(rhsReads) == 0 && len(unpositioned) == 0 {
		return false, nil
	}
	st := taintedLocals(f, summaries)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	for _, variable := range rhsReads {
		if _, tainted := st[variable.name]; tainted {
			return true, nil
		}
	}

	// Parser-produced nodes have positions. Keep the helper total for
	// synthetic or future positionless ASTs without turning shape alone into
	// a precision-loss marker.
	for _, expr := range unpositioned {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if _, tainted := exprTaint(expr, st, summaries); tainted {
			return true, nil
		}
	}
	return false, nil
}

// findFlows reports each sink in a scope that receives remote content.
// exclude names the declarations nested inside this scope. A sink's argument
// expression is collected WITHOUT it, so a call reached only through a closure
// there is still followed -- `include array_map(function(){ return fetch(); },
// $r)[0]` really does receive what that closure returns. Its variables are then
// filtered THROUGH it, because they are graded against this scope's taint
// state and a nested declaration's own parameter or local was never part of
// it. Same split, and same reason, as the return expressions in summaries.go.
func findFlows(
	ctx context.Context, f *scopeFacts, summaries summaryTables, exclude *spanIndex,
) ([]flowResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(f.sinks) == 0 {
		return nil, nil
	}
	st := taintedLocals(f, summaries)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]flowResult, 0, len(f.sinks))
	callIndex := newResolvedCallIndex(f)
	for _, s := range f.sinks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sub := callIndex.apply(collectScope(s.expr)).withoutNestedDeclarationVars(exclude)
		c, tainted := exprTaintFacts(sub, st, summaries)
		if !tainted {
			continue
		}
		source, sourceTruncated := sourceLabel(sub, st, summaries)
		identifiers, identifiersTruncated := identifiersFor(sub)
		out = append(out, flowResult{
			Result: Result{
				Source:      source,
				Identifiers: identifiers,
				Sink:        s.kind,
				Confidence:  c,
			},
			evidenceTruncated: sourceTruncated || identifiersTruncated,
		})
	}
	return out, nil
}

// sourceLabel names the acquiring construct for evidence. It prefers a
// directly visible source call, then a taint-returning callee, then the
// tainted variable that carried the value in. Resolution goes through
// callSites (rather than the bare f.calls name set) so a summarized method
// is matched via the same call-syntax-scoped lookup taintedLocals uses,
// instead of guessing across the function/method namespaces.
func sourceLabel(sub *scopeFacts, st taintState, summaries summaryTables) (string, bool) {
	for _, call := range sub.callNodes {
		if _, ok := sourceConfidence(call); ok {
			return sanitize(calleeName(call.Function), maxSegmentBytes)
		}
	}
	names := make([]string, 0, len(sub.callSites))
	for _, call := range sub.callSites {
		if _, ok := summaries.lookup(call); ok {
			names = append(names, call.name)
		}
	}
	sort.Strings(names)
	if len(names) > 0 {
		return sanitize(names[0], maxSegmentBytes)
	}
	vars := make([]string, 0, len(sub.vars)+len(sub.propNodes))
	for name := range sub.vars {
		if _, ok := st[name]; ok {
			vars = append(vars, name)
		}
	}
	// A property key (e.g. "this->body") is checked separately from the
	// bare-variable loop above: the base variable's own name is not tainted
	// by a property write, so a flow carried entirely by a specific property
	// would otherwise fall through every branch above and report "unknown"
	// instead of naming the property that actually carried it.
	for _, n := range sub.propNodes {
		key := assignedTargetKey(n)
		if key == "" {
			continue
		}
		if _, ok := st[key]; ok {
			vars = append(vars, key)
		}
	}
	sort.Strings(vars)
	if len(vars) > 0 {
		return sanitize("$"+vars[0], maxSegmentBytes)
	}
	return "unknown", false
}

// identifiersFor renders the sanitized, bounded Identifiers list for
// evidence: every distinct variable and call name appearing anywhere in the
// sink's own expression, tainted or not. This is not a laundering path --
// there is no ordering or filtering by whether a name actually carried the
// tainted value, only alphabetical sort for deterministic output.
func identifiersFor(sub *scopeFacts) ([]string, bool) {
	segs := make([]string, 0, len(sub.vars)+len(sub.calls))
	for name := range sub.vars {
		if name != "" {
			segs = append(segs, "$"+name)
		}
	}
	for name := range sub.calls {
		segs = append(segs, name)
	}
	sort.Strings(segs)
	return truncateChain(segs)
}

// dedupeAndSort collapses flows that render the same display endpoint pair
// and orders results so repeated runs are byte-identical.
func dedupeAndSort(in []flowResult) []flowResult {
	seen := map[string]int{}
	out := make([]flowResult, 0, len(in))
	for _, r := range in {
		key := r.Source + "\x00" + r.Sink
		if idx, ok := seen[key]; ok {
			if r.Confidence > out[idx].Confidence {
				out[idx].Confidence = r.Confidence
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		if out[i].Sink != out[j].Sink {
			return out[i].Sink < out[j].Sink
		}
		return strings.Join(out[i].Identifiers, ",") < strings.Join(out[j].Identifiers, ",")
	})
	return out
}

// activeTaint finds the strongest confidence among an already-collected
// subtree's source calls, summarized calls, and tainted variable reads. It also
// returns source positions so decoder correlation stays linearithmic rather
// than recursively recollecting every nested decoder argument.
// A variable name is looked up in a taintState in exactly five places in this
// package, and every one of them must be fed by facts collected WITH
// declaration exclusion, or a nested declaration's own parameter or local
// borrows an identically named outer variable's taint and reports a flow on
// clean code. Names like $data, $content and $url recur constantly in real
// PHP, so a bare collision is enough. The five, and what keeps each scoped:
//
//	solveAssignments             origins built from the scope's own facts
//	hasUnresolvableTaintedTarget the scope's own facts
//	sourceLabel                  a filtered sub (vars rebuilt to match)
//	stateFor                     taintedLocals over a per-scope facts value
//	activeTaint (below)          see the three feeders named next
//
// activeTaint is reached only through exprTaintFacts, which has three
// feeders: evalBodySummary and findFlows, both of which collect their
// expression WITHOUT exclusion so that a call reached only through a nested
// closure is still followed, and then filter its variable side back through
// the scope's exclusion index; and exprTaint, whose two callers are both
// reachable only for an AST node carrying no position, which this parser does
// not produce.
//
// Anything new that grades an expression against a scope's taint state joins
// this list and needs the same treatment. Fixing one instance at a time does
// not work here: this defect was found and fixed three separate times -- in
// the summaries path, in the sink path, and in the capture walk -- before the
// enumeration above made it possible to say the class was closed rather than
// merely that no more instances had turned up.
func activeTaint(sub *scopeFacts, st taintState, summaries summaryTables) (Confidence, bool, []nodeSpan) {
	best := ConfidenceLow
	found := false
	origins := make([]nodeSpan, 0)
	for _, call := range sub.callNodes {
		if c, ok := sourceConfidence(call); ok {
			found = true
			if c > best {
				best = c
			}
			if span, ok := spanOf(call); ok {
				origins = append(origins, span)
			}
		}
	}
	for _, call := range sub.callSites {
		if c, ok := summaries.lookup(call); ok {
			found = true
			if c > best {
				best = c
			}
			if span, ok := spanOf(call.node); ok {
				origins = append(origins, span)
			}
		}
	}
	for _, variable := range sub.readVarNodes() {
		if c, ok := st[variable.name]; ok {
			found = true
			if c > best {
				best = c
			}
			if span, ok := spanOf(variable.node); ok {
				origins = append(origins, span)
			}
		}
	}
	return best, found, origins
}
