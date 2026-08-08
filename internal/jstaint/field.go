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
	return value{allocs: allocSet{{id: id}: true}, allocOnly: true}
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
	return value{allocs: allocSet{{id: id}: true}, allocOnly: true}
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
		if hasAllocID(v.allocs, from) {
			v.allocs = replaceAlloc(v.allocs, from, to)
			st.env[k] = v
		}
	}
	for node, v := range st.captures {
		if hasAllocID(v.allocs, from) {
			v.allocs = replaceAlloc(v.allocs, from, to)
			st.captures[node] = v
		}
	}
	for _, o := range st.heap {
		for fk, fv := range o.fields {
			if hasAllocID(fv.allocs, from) {
				fv.allocs = replaceAlloc(fv.allocs, from, to)
				o.fields[fk] = fv
			}
		}
		if hasAllocID(o.wild.allocs, from) {
			o.wild.allocs = replaceAlloc(o.wild.allocs, from, to)
		}
		if hasAllocID(o.wildReq.allocs, from) {
			o.wildReq.allocs = replaceAlloc(o.wildReq.allocs, from, to)
		}
		if hasAllocID(o.elem.allocs, from) {
			o.elem.allocs = replaceAlloc(o.elem.allocs, from, to)
		}
	}
}

func replaceAlloc(s allocSet, from, to allocID) allocSet {
	out := make(allocSet, len(s))
	for ref := range s {
		if ref.id == from {
			ref.id = to
			out[ref] = true
		} else {
			out[ref] = true
		}
	}
	return out
}

func valueCarriesDepthZero(st *state, v value) bool {
	if taintCarriesDepthZero(v.scalar) {
		return true
	}
	seen := map[allocRef]bool{}
	stack := make([]allocRef, 0, len(v.allocs))
	for ref := range v.allocs {
		stack = append(stack, ref)
	}
	push := func(parent allocRef, child value) bool {
		child = applyRefDepth(child, parent)
		for fact := range child.scalar {
			if fact.callDepth == 0 {
				return true
			}
		}
		for ref := range child.allocs {
			if !seen[ref] {
				stack = append(stack, ref)
			}
		}
		return false
	}
	for len(stack) > 0 {
		ref := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[ref] {
			continue
		}
		seen[ref] = true
		o := st.heap[ref.id]
		if o == nil {
			continue
		}
		for _, field := range o.fields {
			if push(ref, field) {
				return true
			}
		}
		if push(ref, o.elem) || push(ref, o.wild) || push(ref, o.wildReq) {
			return true
		}
	}
	return false
}

func taintCarriesDepth(ts taintSet, depth int) bool {
	for fact := range ts {
		if int(fact.callDepth) == depth {
			return true
		}
	}
	return false
}

func taintCarriesDepthZero(ts taintSet) bool {
	return taintCarriesDepth(ts, 0)
}

// resetAllocRefDepth records that an allocation now carries a fact created in
// the current invocation. Existing field facts retain their own depth, but
// aliases must no longer impose an older return-path barrier on the new write.
func resetAllocRefDepth(st *state, ids map[allocID]bool) {
	reset := func(v value) value {
		if len(v.allocs) == 0 {
			return v
		}
		refs := make(allocSet, len(v.allocs))
		for ref := range v.allocs {
			if ids[ref.id] {
				ref.minDepth = 0
				ref.advance = 0
			}
			refs[ref] = true
		}
		v.allocs = refs
		return v
	}
	for cv, v := range st.env {
		st.env[cv] = reset(v)
	}
	for node, v := range st.captures {
		st.captures[node] = reset(v)
	}
	for _, o := range st.heap {
		for name, v := range o.fields {
			o.fields[name] = reset(v)
		}
		o.elem = reset(o.elem)
		o.wild = reset(o.wild)
		o.wildReq = reset(o.wildReq)
	}
}

func hasAllocID(s allocSet, id allocID) bool {
	for ref := range s {
		if ref.id == id {
			return true
		}
	}
	return false
}

func allocsConstrained(s allocSet) bool {
	for ref := range s {
		if ref.minDepth != 0 || ref.advance != 0 {
			return true
		}
	}
	return false
}

// writeField taints one field on the receiver's allocations. A clean write is a
// strong update (it can clear taint) only when the receiver is exactly one
// current instance; a summary field or a receiver with several possible
// allocations is weak-updated, so it cannot lose taint an aliased path still
// carries. Statically known array indexes are distinct fields; unresolved array
// elements and wildcard writes stay weak because they can represent many keys.
func (a *analysis) writeField(st *state, recv value, key fieldKey, rhs value) {
	ids := uniqueAllocIDs(recv.allocs)
	strong := recv.allocOnly && len(ids) == 1 && soleCurrent(recv.allocs)
	for id := range ids {
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
	if a.callDepth == 0 && allocsConstrained(recv.allocs) && valueCarriesDepthZero(st, rhs) {
		resetAllocRefDepth(st, ids)
	}
	a.fact()
}

// deleteField removes one statically known field when the receiver is a lone
// current instance. A delete through a summary or ambiguous receiver is a weak
// update, so it cannot prove that every represented runtime field disappeared.
func (a *analysis) deleteField(st *state, recv value, key fieldKey) {
	ids := uniqueAllocIDs(recv.allocs)
	if len(ids) != 1 || !soleCurrent(recv.allocs) {
		return
	}
	for id := range ids {
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
	for ref := range s {
		if ref.id.summary {
			return false
		}
	}
	return len(s) != 0
}

func uniqueAllocIDs(s allocSet) map[allocID]bool {
	ids := make(map[allocID]bool, len(s))
	for ref := range s {
		ids[ref.id] = true
	}
	return ids
}

// readField reads one field across every allocation the receiver may reference.
func (a *analysis) readField(st *state, recv value, key fieldKey) value {
	var out value
	have := false
	definiteAlloc := recv.allocOnly && len(recv.allocs) != 0
	definiteField := definiteAlloc
	for ref := range recv.allocs {
		o := st.heap[ref.id]
		if o == nil {
			definiteAlloc = false
			definiteField = false
			continue
		}
		fv, definite := getField(o, key)
		fv = applyRefDepth(fv, ref)
		out, have = mergePresentValue(out, have, fv)
		if !definite || !fv.allocOnly {
			definiteAlloc = false
		}
		if !definite {
			definiteField = false
		}
	}
	if !have {
		return value{}
	}
	out.allocOnly = definiteAlloc
	if !definiteField {
		out.scheme = schemeState{}
	}
	return out
}

func fieldDefinitelyPresent(st *state, recv value, key fieldKey) bool {
	if !recv.allocOnly || len(recv.allocs) == 0 {
		return false
	}
	seen := map[allocID]bool{}
	for ref := range recv.allocs {
		if seen[ref.id] {
			continue
		}
		seen[ref.id] = true
		o := st.heap[ref.id]
		if o == nil {
			return false
		}
		if _, definite := getField(o, key); !definite {
			return false
		}
	}
	return len(seen) != 0
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
	for ref := range v.allocs {
		if ts, cyclic := a.walkStringify(st, ref); !cyclic {
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

func stringifyValues(o *object, ref allocRef) []stringifySlot {
	values := make([]stringifySlot, 0, len(o.fields)+3)
	for name, fv := range o.fields {
		if !o.array || isArrayIndexName(name) {
			values = append(values, stringifySlot{value: applyRefDepth(fv, ref), optional: !o.must[name]})
		}
	}
	if o.elemMay {
		values = append(values, stringifySlot{
			value: applyRefDepth(o.elem, ref), optional: !o.elemMust, collection: true,
		})
	}
	if o.wildMay {
		values = append(values, stringifySlot{value: applyRefDepth(o.wild, ref), optional: true})
	}
	if o.wildMust && !o.array {
		values = append(values, stringifySlot{value: applyRefDepth(o.wildReq, ref)})
	}
	return values
}

func arrayNeighbors(o *object, ref allocRef, addScalar func(taintSet)) []allocRef {
	if !o.array {
		return nil
	}
	var nbrs []allocRef
	collect := func(v value) {
		v = applyRefDepth(v, ref)
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

func (a *analysis) walkStringify(st *state, root allocRef) (taintSet, bool) {
	// Preserve each field's allocation set as one group: its members are runtime
	// alternatives, while separate fields and collected array elements must all
	// serialize. Starting with leaf allocations and satisfying dependent groups
	// computes the acyclic choices without mistaking a diamond for a cycle.
	nodes := map[allocRef][]stringifySlot{}
	stack := []allocRef{root}
	for len(stack) > 0 {
		if !a.alive() {
			return nil, false
		}
		ref := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := nodes[ref]; ok {
			continue
		}
		var values []stringifySlot
		if o := st.heap[ref.id]; o != nil {
			values = stringifyValues(o, ref)
		}
		nodes[ref] = values
		for _, slot := range values {
			for aid := range slot.value.allocs {
				if _, seen := nodes[aid]; !seen {
					stack = append(stack, aid)
				}
			}
		}
	}

	type dependencyGroup struct {
		owner     allocRef
		satisfied bool
	}
	var groups []dependencyGroup
	pending := make(map[allocRef]int, len(nodes))
	reverse := map[allocRef][]int{}
	for ref, values := range nodes {
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
					groups = append(groups, dependencyGroup{owner: ref})
					pending[ref]++
					reverse[aid] = append(reverse[aid], group)
				}
				continue
			}
			group := len(groups)
			groups = append(groups, dependencyGroup{owner: ref})
			pending[ref]++
			for aid := range fv.allocs {
				reverse[aid] = append(reverse[aid], group)
			}
		}
	}

	serializable := make(map[allocRef]bool, len(nodes))
	queue := make([]allocRef, 0, len(nodes))
	for ref := range nodes {
		if pending[ref] == 0 {
			queue = append(queue, ref)
		}
	}
	for len(queue) > 0 {
		if !a.alive() {
			return nil, false
		}
		ref := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if serializable[ref] {
			continue
		}
		serializable[ref] = true
		for _, group := range reverse[ref] {
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
	done := map[allocRef]bool{}
	stack = append(stack, root)
	for len(stack) > 0 {
		if !a.alive() {
			return out, false
		}
		ref := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if done[ref] || !serializable[ref] {
			continue
		}
		done[ref] = true
		for _, slot := range nodes[ref] {
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
	done := map[allocRef]bool{}
	stack := make([]allocRef, 0, len(v.allocs))
	for ref := range v.allocs {
		stack = append(stack, ref)
	}
	for len(stack) > 0 {
		if !a.alive() {
			return out
		}
		ref := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if done[ref] {
			continue
		}
		done[ref] = true
		o := st.heap[ref.id]
		if o == nil || !o.array {
			continue
		}
		for _, aid := range arrayNeighbors(o, ref, func(ts taintSet) { out = mergeTaint(out, ts) }) {
			if !done[aid] {
				stack = append(stack, aid)
			}
		}
	}
	return out
}

// numberAllocSites assigns a deterministic site id to every object, array, new
// expression, and modeled createElement call in source order. The ids drive the
// two-class recency model.
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
	switch e := node.(type) {
	case *js.ObjectExpr, *js.ArrayExpr, *js.NewExpr:
		n.sites[node] = n.next
		n.next++
	case *js.CallExpr:
		// A createElement call allocates a fresh element, so it needs its own site
		// for the resource-element receiver model.
		if prop, _, ok := memberAccess(ungroupExpr(e.X)); ok && prop == "createElement" {
			n.sites[node] = n.next
			n.next++
		}
	}
	return n
}
