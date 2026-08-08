package jstaint

import "github.com/tdewolff/parse/v2/js"

// allocate installs a fresh instance at site and returns a value referencing it.
// Inside a loop the instance is summarized, because the site can produce many
// runtime objects; otherwise it is the current singleton for this control-flow
// path. A prior current instance at the same site is promoted to the summary
// class first, so a re-allocation cannot clear taint on an earlier instance that
// was aliased or published.
func (a *analysis) allocate(st *state, site int, inLoop bool) value {
	a.promoteCurrent(st, site)
	id := allocID{site: site, summary: inLoop}
	fresh := &object{}
	if inLoop {
		if old, ok := st.heap[id]; ok {
			st.heap[id] = mergeObject(old, fresh)
		} else {
			st.heap[id] = fresh
		}
	} else {
		st.heap[id] = fresh
	}
	a.fact()
	return value{allocs: allocSet{id: true}, allocOnly: true}
}

// installLiteral publishes a fully evaluated object or array literal at its
// allocation site. Building it separately preserves construction semantics
// before loop instances are merged into a summary.
func (a *analysis) installLiteral(st *state, site int, inLoop bool, fresh *object) value {
	id := allocID{site: site, summary: inLoop}
	if inLoop {
		if old, ok := st.heap[id]; ok {
			st.heap[id] = mergeObject(old, fresh)
		} else {
			st.heap[id] = fresh
		}
	} else {
		st.heap[id] = fresh
	}
	a.fact()
	return value{allocs: allocSet{id: true}, allocOnly: true}
}

// promoteCurrent moves any current instance at site into the summary class and
// rewrites every reference to it. This is how two recency classes model an
// unbounded number of runtime objects: the escaped or aliased earlier object
// survives in the summary while a fresh current instance takes its place.
func (a *analysis) promoteCurrent(st *state, site int) {
	from := allocID{site: site, summary: false}
	cur, ok := st.heap[from]
	if !ok {
		return
	}
	to := allocID{site: site, summary: true}
	if ex, ok := st.heap[to]; ok {
		st.heap[to] = mergeObject(ex, cur)
	} else {
		st.heap[to] = cur
	}
	delete(st.heap, from)
	rewriteAlloc(st, from, to)
}

func rewriteAlloc(st *state, from, to allocID) {
	for k, v := range st.env {
		if v.allocs[from] {
			st.env[k] = value{scalar: v.scalar, allocs: replaceAlloc(v.allocs, from, to), allocOnly: v.allocOnly}
		}
	}
	for _, o := range st.heap {
		for fk, fv := range o.fields {
			if fv.allocs[from] {
				o.fields[fk] = value{
					scalar: fv.scalar, allocs: replaceAlloc(fv.allocs, from, to), allocOnly: fv.allocOnly,
				}
			}
		}
		if o.wild.allocs[from] {
			o.wild = value{
				scalar: o.wild.scalar, allocs: replaceAlloc(o.wild.allocs, from, to), allocOnly: o.wild.allocOnly,
			}
		}
		if o.wildReq.allocs[from] {
			o.wildReq = value{
				scalar: o.wildReq.scalar, allocs: replaceAlloc(o.wildReq.allocs, from, to),
				allocOnly: o.wildReq.allocOnly,
			}
		}
		if o.elem.allocs[from] {
			o.elem = value{
				scalar: o.elem.scalar, allocs: replaceAlloc(o.elem.allocs, from, to), allocOnly: o.elem.allocOnly,
			}
		}
	}
}

func replaceAlloc(s allocSet, from, to allocID) allocSet {
	out := make(allocSet, len(s))
	for k := range s {
		if k == from {
			out[to] = true
		} else {
			out[k] = true
		}
	}
	return out
}

// writeField taints one field on the receiver's allocations. A clean write is a
// strong update (it can clear taint) only when the receiver is exactly one
// current instance; a summary field or a receiver with several possible
// allocations is weak-updated, so it cannot lose taint an aliased path still
// carries. Statically known array indexes are distinct fields; unresolved array
// elements and wildcard writes stay weak because they can represent many keys.
func (a *analysis) writeField(st *state, recv value, key fieldKey, rhs value) {
	strong := len(recv.allocs) == 1 && soleCurrent(recv.allocs)
	for id := range recv.allocs {
		o := st.heap[id]
		if o == nil {
			o = &object{}
			st.heap[id] = o
		}
		switch key.kind {
		case fieldNamed:
			o.setNamed(key.name, rhs, strong && !id.summary)
		case fieldElem:
			if key.name != "" {
				o.setNamed(key.name, rhs, strong && !id.summary)
			} else {
				o.weakElem(rhs, strong && !id.summary)
			}
		default:
			o.writeWild(rhs, strong && !id.summary)
		}
	}
	a.fact()
}

// deleteField removes one statically known field when the receiver is a lone
// current instance. A delete through a summary or ambiguous receiver is a weak
// update, so it cannot prove that every represented runtime field disappeared.
func (a *analysis) deleteField(st *state, recv value, key fieldKey) {
	if len(recv.allocs) != 1 || !soleCurrent(recv.allocs) {
		return
	}
	for id := range recv.allocs {
		o := st.heap[id]
		if o == nil {
			return
		}
		switch key.kind {
		case fieldNamed:
			o.deleteNamed(key.name)
		case fieldElem:
			if key.name == "" {
				return
			}
			o.deleteNamed(key.name)
		default:
			return
		}
		a.fact()
	}
}

func soleCurrent(s allocSet) bool {
	for id := range s {
		return !id.summary
	}
	return false
}

// readField reads one field across every allocation the receiver may reference.
func (a *analysis) readField(st *state, recv value, key fieldKey) value {
	var out value
	have := false
	definiteAlloc := recv.allocOnly && len(recv.allocs) != 0
	for id := range recv.allocs {
		o := st.heap[id]
		if o == nil {
			definiteAlloc = false
			continue
		}
		fv, definite := getField(o, key)
		out, have = mergePresentValue(out, have, fv)
		if !definite || !fv.allocOnly {
			definiteAlloc = false
		}
	}
	if !have {
		return value{}
	}
	out.allocOnly = definiteAlloc
	return out
}

// serializeStringify returns the scalar taint JSON.stringify(v) would carry.
// Reachable field taint is folded in by an iterative graph walk. An
// allocation whose reachable graph contains a cycle contributes no value, because
// the runtime throws before producing output; a union that also holds an acyclic
// alternative keeps the acyclic taint. The walk is iterative because a heap graph
// built through assignments can be far deeper than the AST, and a recursive walk
// could overflow the Go stack, a fatal error recover cannot intercept.
func (a *analysis) serializeStringify(st *state, v value) taintSet {
	out := v.scalar
	for id := range v.allocs {
		if ts, cyclic := a.walkStringify(st, id); !cyclic {
			out = mergeTaint(out, ts)
		}
	}
	return out
}

type stringifySlot struct {
	value      value
	optional   bool
	collection bool
}

func stringifyValues(o *object) []stringifySlot {
	values := make([]stringifySlot, 0, len(o.fields)+3)
	for name, fv := range o.fields {
		if !o.array || isArrayIndexName(name) {
			values = append(values, stringifySlot{value: fv, optional: !o.must[name]})
		}
	}
	if o.elemMay {
		values = append(values, stringifySlot{value: o.elem, optional: !o.elemMust, collection: true})
	}
	if o.wildMay {
		values = append(values, stringifySlot{value: o.wild, optional: true})
	}
	if o.wildMust && !o.array {
		values = append(values, stringifySlot{value: o.wildReq})
	}
	return values
}

func arrayNeighbors(o *object, addScalar func(taintSet)) []allocID {
	if !o.array {
		return nil
	}
	var nbrs []allocID
	collect := func(v value) {
		addScalar(v.scalar)
		for aid := range v.allocs {
			nbrs = append(nbrs, aid)
		}
	}
	for name, fv := range o.fields {
		if isArrayIndexName(name) {
			collect(fv)
		}
	}
	if o.elemMay {
		collect(o.elem)
	}
	if o.wildMay {
		collect(o.wild)
	}
	return nbrs
}

func (a *analysis) walkStringify(st *state, root allocID) (taintSet, bool) {
	// Preserve each field's allocation set as one group: its members are runtime
	// alternatives, while separate fields and collected array elements must all
	// serialize. Starting with leaf allocations and satisfying dependent groups
	// computes the acyclic choices without mistaking a diamond for a cycle.
	nodes := map[allocID][]stringifySlot{}
	stack := []allocID{root}
	for len(stack) > 0 {
		if !a.alive() {
			return nil, false
		}
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := nodes[id]; ok {
			continue
		}
		var values []stringifySlot
		if o := st.heap[id]; o != nil {
			values = stringifyValues(o)
		}
		nodes[id] = values
		for _, slot := range values {
			for aid := range slot.value.allocs {
				if _, seen := nodes[aid]; !seen {
					stack = append(stack, aid)
				}
			}
		}
	}

	type dependencyGroup struct {
		owner     allocID
		satisfied bool
	}
	var groups []dependencyGroup
	pending := make(map[allocID]int, len(nodes))
	reverse := map[allocID][]int{}
	for id, values := range nodes {
		for _, slot := range values {
			fv := slot.value
			if slot.optional {
				continue
			}
			if len(fv.allocs) == 0 || (!slot.collection && (!fv.allocOnly || len(fv.scalar) != 0)) {
				continue
			}
			if slot.collection {
				for aid := range fv.allocs {
					group := len(groups)
					groups = append(groups, dependencyGroup{owner: id})
					pending[id]++
					reverse[aid] = append(reverse[aid], group)
				}
				continue
			}
			group := len(groups)
			groups = append(groups, dependencyGroup{owner: id})
			pending[id]++
			for aid := range fv.allocs {
				reverse[aid] = append(reverse[aid], group)
			}
		}
	}

	serializable := make(map[allocID]bool, len(nodes))
	queue := make([]allocID, 0, len(nodes))
	for id := range nodes {
		if pending[id] == 0 {
			queue = append(queue, id)
		}
	}
	for len(queue) > 0 {
		if !a.alive() {
			return nil, false
		}
		id := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if serializable[id] {
			continue
		}
		serializable[id] = true
		for _, group := range reverse[id] {
			if groups[group].satisfied {
				continue
			}
			groups[group].satisfied = true
			owner := groups[group].owner
			pending[owner]--
			if pending[owner] == 0 {
				queue = append(queue, owner)
			}
		}
	}
	if !serializable[root] {
		return nil, true
	}

	var out taintSet
	done := map[allocID]bool{}
	stack = append(stack, root)
	for len(stack) > 0 {
		if !a.alive() {
			return out, false
		}
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if done[id] || !serializable[id] {
			continue
		}
		done[id] = true
		for _, slot := range nodes[id] {
			fv := slot.value
			out = mergeTaint(out, fv.scalar)
			for aid := range fv.allocs {
				if serializable[aid] && !done[aid] {
					stack = append(stack, aid)
				}
			}
		}
	}
	return out, false
}

// serializeArray returns the scalar taint a join or array serialization carries.
// A self-referential element contributes no taint when revisited, but other
// tainted elements still propagate and the walk always terminates. It is
// iterative for the same stack-safety reason as serializeStringify.
func (a *analysis) serializeArray(st *state, v value) taintSet {
	var out taintSet
	done := map[allocID]bool{}
	stack := make([]allocID, 0, len(v.allocs))
	for id := range v.allocs {
		stack = append(stack, id)
	}
	for len(stack) > 0 {
		if !a.alive() {
			return out
		}
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if done[id] {
			continue
		}
		done[id] = true
		o := st.heap[id]
		if o == nil || !o.array {
			continue
		}
		for _, aid := range arrayNeighbors(o, func(ts taintSet) { out = mergeTaint(out, ts) }) {
			if !done[aid] {
				stack = append(stack, aid)
			}
		}
	}
	return out
}

// numberAllocSites assigns a deterministic site id to every object, array, and
// new expression in source order. The ids drive the two-class recency model.
func numberAllocSites(ast *js.AST) map[js.INode]int {
	n := &siteNumberer{sites: map[js.INode]int{}}
	js.Walk(n, ast)
	return n.sites
}

type siteNumberer struct {
	sites map[js.INode]int
	next  int
}

func (n *siteNumberer) Exit(js.INode) {}

func (n *siteNumberer) Enter(node js.INode) js.IVisitor {
	if walkComputedClassName(n, node) {
		return n
	}
	switch node.(type) {
	case *js.ObjectExpr, *js.ArrayExpr, *js.NewExpr:
		n.sites[node] = n.next
		n.next++
	}
	return n
}
