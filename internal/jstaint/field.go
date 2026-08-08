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
	if inLoop {
		if _, ok := st.heap[id]; !ok {
			st.heap[id] = &object{}
		}
	} else {
		st.heap[id] = &object{}
	}
	a.fact()
	return value{allocs: allocSet{id: true}}
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
			st.env[k] = value{scalar: v.scalar, allocs: replaceAlloc(v.allocs, from, to)}
		}
	}
	for _, o := range st.heap {
		for fk, fv := range o.fields {
			if fv.allocs[from] {
				o.fields[fk] = value{scalar: fv.scalar, allocs: replaceAlloc(fv.allocs, from, to)}
			}
		}
		if o.wild.allocs[from] {
			o.wild = value{scalar: o.wild.scalar, allocs: replaceAlloc(o.wild.allocs, from, to)}
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
// carries. Array-element and wildcard writes are always weak.
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
			o.weakElem(rhs)
		default:
			o.wild = mergeValue(o.wild, rhs)
		}
	}
	a.fact()
}

func soleCurrent(s allocSet) bool {
	for id := range s {
		return !id.summary
	}
	return false
}

// writeFieldWeak taints a field without ever clearing existing taint. It models a
// write that only may execute, such as the right side of a logical assignment.
func (a *analysis) writeFieldWeak(st *state, recv value, key fieldKey, rhs value) {
	for id := range recv.allocs {
		o := st.heap[id]
		if o == nil {
			o = &object{}
			st.heap[id] = o
		}
		switch key.kind {
		case fieldNamed:
			o.setNamed(key.name, rhs, false)
		case fieldElem:
			o.weakElem(rhs)
		default:
			o.wild = mergeValue(o.wild, rhs)
		}
	}
	a.fact()
}

// readField reads one field across every allocation the receiver may reference.
func (a *analysis) readField(st *state, recv value, key fieldKey) value {
	var out value
	for id := range recv.allocs {
		if o := st.heap[id]; o != nil {
			out = mergeValue(out, getField(o, key))
		}
	}
	return out
}

// serializeStringify returns the scalar taint JSON.stringify(v) would carry.
// Reachable field taint is folded in by an iterative depth-first walk. An
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

func allocNeighbors(o *object, addScalar func(taintSet)) []allocID {
	var nbrs []allocID
	collect := func(v value) {
		addScalar(v.scalar)
		for aid := range v.allocs {
			nbrs = append(nbrs, aid)
		}
	}
	for _, fv := range o.fields {
		collect(fv)
	}
	collect(o.wild)
	return nbrs
}

func (a *analysis) walkStringify(st *state, root allocID) (taintSet, bool) {
	const white, gray, black = 0, 1, 2
	color := map[allocID]int{}
	var out taintSet
	cyclic := false
	type frame struct {
		id   allocID
		nbrs []allocID
		i    int
	}
	visit := func(id allocID) frame {
		color[id] = gray
		var nbrs []allocID
		if o := st.heap[id]; o != nil {
			nbrs = allocNeighbors(o, func(ts taintSet) { out = mergeTaint(out, ts) })
		}
		return frame{id: id, nbrs: nbrs}
	}
	stack := []frame{visit(root)}
	for len(stack) > 0 {
		if !a.alive() {
			return out, cyclic
		}
		top := &stack[len(stack)-1]
		if top.i >= len(top.nbrs) {
			color[top.id] = black
			stack = stack[:len(stack)-1]
			continue
		}
		nb := top.nbrs[top.i]
		top.i++
		switch color[nb] {
		case white:
			stack = append(stack, visit(nb))
		case gray:
			cyclic = true
		}
	}
	return out, cyclic
}

// serializeArray returns the scalar taint a join or array serialization carries.
// A self-referential element contributes no taint when revisited, but other
// tainted elements still propagate and the walk always terminates. It is
// iterative for the same stack-safety reason as serializeStringify.
func (a *analysis) serializeArray(st *state, v value) taintSet {
	out := v.scalar
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
		if o == nil {
			continue
		}
		for _, aid := range allocNeighbors(o, func(ts taintSet) { out = mergeTaint(out, ts) }) {
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
