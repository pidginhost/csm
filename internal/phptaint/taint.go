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
				variable: assignedVarName(a.Var), assignment: -1,
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
		target := assignedVarName(reference.Expr)
		source := assignedVarName(reference.Var)
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
	name := assignedVarName(target)
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
				changed = st.raise(assignedVarName(assignment.Var), confidence) || changed
			}
		}
		for _, assignment := range f.references {
			if confidence, tainted := exprTaint(assignment.Expr, st, summaries); tainted {
				changed = st.raise(assignedVarName(assignment.Var), confidence) || changed
			}
			if confidence, tainted := exprTaint(assignment.Var, st, summaries); tainted {
				changed = st.raise(assignedVarName(assignment.Expr), confidence) || changed
			}
		}
		for _, assignment := range f.concats {
			if confidence, tainted := exprTaint(assignment.Expr, st, summaries); tainted {
				changed = st.raise(assignedVarName(assignment.Var), confidence) || changed
			}
		}
		if !changed {
			return st
		}
	}
	return st
}

// assignedVarName returns the root local variable written by an assignment.
// Array elements and object properties taint their containing value as a whole,
// which is the documented version-1 precision model.
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

// exprTaint reports whether an expression carries remote content, and with
// what confidence. It collects the subtree once and correlates decoder inputs
// by source positions, without recursing over the parsed structure.
func exprTaint(e ast.Vertex, st taintState, summaries summaryTables) (Confidence, bool) {
	if e == nil {
		return ConfidenceLow, false
	}
	sub := collectScope(e)
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

// findFlows reports each sink in a scope that receives remote content.
func findFlows(ctx context.Context, f *scopeFacts, summaries summaryTables) ([]flowResult, error) {
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
	for _, s := range f.sinks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c, tainted := exprTaint(s.expr, st, summaries)
		if !tainted {
			continue
		}
		source, sourceTruncated := sourceLabel(s.expr, st, summaries)
		via, viaTruncated := chainFor(s.expr)
		out = append(out, flowResult{
			Result: Result{
				Source:     source,
				Via:        via,
				Sink:       s.kind,
				Confidence: c,
			},
			evidenceTruncated: sourceTruncated || viaTruncated,
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
func sourceLabel(e ast.Vertex, st taintState, summaries summaryTables) (string, bool) {
	sub := collectScope(e)
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
	vars := make([]string, 0, len(sub.vars))
	for name := range sub.vars {
		if _, ok := st[name]; ok {
			vars = append(vars, name)
		}
	}
	sort.Strings(vars)
	if len(vars) > 0 {
		return sanitize("$"+vars[0], maxSegmentBytes)
	}
	return "unknown", false
}

// chainFor renders the sanitized, bounded laundering chain for evidence.
func chainFor(e ast.Vertex) ([]string, bool) {
	sub := collectScope(e)
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
		return strings.Join(out[i].Via, ",") < strings.Join(out[j].Via, ",")
	})
	return out
}

// activeTaint finds the strongest confidence among an already-collected
// subtree's source calls, summarized calls, and tainted variable reads. It also
// returns source positions so decoder correlation stays linearithmic rather
// than recursively recollecting every nested decoder argument.
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
