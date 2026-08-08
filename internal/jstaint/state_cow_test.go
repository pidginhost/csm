package jstaint

import (
	"testing"

	"github.com/tdewolff/parse/v2/js"
)

// The copy-on-write state representation shares env, captures, and heap between
// a state and its clones until one side writes. These tests pin the aliasing
// contract: a mutation through the ownership barrier on one state must never be
// observable through any other state sharing its storage.

func cowTaint(source int, via ...string) taintSet {
	return taintSet{taintFact{source: source}: via}
}

func cowValue(source int) value {
	return value{scalar: cowTaint(source)}
}

func newCOWFixture() (*state, *js.Var, js.INode, allocID) {
	st := newState()
	v := &js.Var{Data: []byte("x"), Decl: js.VariableDecl}
	node := &js.LiteralExpr{}
	id := allocID{site: 7}
	st.setEnv(v, cowValue(1))
	st.setCapture(node, cowValue(2))
	o := &object{}
	o.setNamed("k", cowValue(3), true)
	st.installObject(id, o)
	return st, v, node, id
}

func TestCOW_CloneIsolatesEnvCapturesAndHeap(t *testing.T) {
	parent, v, node, id := newCOWFixture()
	child := parent.clone()

	child.setEnv(v, cowValue(10))
	child.setCapture(node, cowValue(20))
	co := child.mutObject(id)
	co.setNamed("k", cowValue(30), true)

	if !valueEqual(parent.env[v], cowValue(1)) {
		t.Errorf("child env write leaked into parent: %+v", parent.env[v])
	}
	if !valueEqual(parent.captures[node], cowValue(2)) {
		t.Errorf("child capture write leaked into parent: %+v", parent.captures[node])
	}
	if got := parent.heap[id].fields["k"]; !valueEqual(got, cowValue(3)) {
		t.Errorf("child object write leaked into parent: %+v", got)
	}

	parent.setEnv(v, cowValue(100))
	parent.delCapture(node)
	po := parent.mutObject(id)
	po.deleteNamed("k")

	if !valueEqual(child.env[v], cowValue(10)) {
		t.Errorf("parent env write leaked into child: %+v", child.env[v])
	}
	if !valueEqual(child.captures[node], cowValue(20)) {
		t.Errorf("parent capture delete leaked into child: %+v", child.captures[node])
	}
	if got := child.heap[id].fields["k"]; !valueEqual(got, cowValue(30)) {
		t.Errorf("parent object delete leaked into child: %+v", got)
	}
}

func TestCOW_UntouchedCloneEqualsParent(t *testing.T) {
	parent, _, _, _ := newCOWFixture()
	child := parent.clone()
	if !stateEqual(parent, child) {
		t.Fatal("clone must start equal to its parent")
	}
}

func TestCOW_MergeStateSharesObjectsSafely(t *testing.T) {
	base, v, _, id := newCOWFixture()
	a := base.clone()
	b := base.clone()
	merged := mergeState(a, b)

	mo := merged.mutObject(id)
	mo.setNamed("k", cowValue(40), true)
	merged.setEnv(v, cowValue(41))

	for name, st := range map[string]*state{"base": base, "a": a, "b": b} {
		if got := st.heap[id].fields["k"]; !valueEqual(got, cowValue(3)) {
			t.Errorf("merge-side object write leaked into %s: %+v", name, got)
		}
		if !valueEqual(st.env[v], cowValue(1)) {
			t.Errorf("merge-side env write leaked into %s: %+v", name, st.env[v])
		}
	}

	ao := a.mutObject(id)
	ao.setNamed("k", cowValue(50), true)
	if got := merged.heap[id].fields["k"]; !valueEqual(got, cowValue(40)) {
		t.Errorf("input mutation after merge leaked into merged: %+v", got)
	}
}

func TestCOW_ReplaceWithKeepsSharersIsolated(t *testing.T) {
	base, v, _, id := newCOWFixture()
	sibling := base.clone()

	temp := base.clone()
	temp.setEnv(v, cowValue(60))
	to := temp.mutObject(id)
	to.setNamed("k", cowValue(61), true)

	base.replaceWith(temp)
	bo := base.mutObject(id)
	bo.setNamed("k", cowValue(62), true)
	base.setEnv(v, cowValue(63))

	if !valueEqual(sibling.env[v], cowValue(1)) {
		t.Errorf("replaceWith mutation leaked into sibling env: %+v", sibling.env[v])
	}
	if got := sibling.heap[id].fields["k"]; !valueEqual(got, cowValue(3)) {
		t.Errorf("replaceWith mutation leaked into sibling heap: %+v", got)
	}
}

// markSocketsObservable runs on the published fixpoint state while the previous
// global is still live and about to be compared with stateEqual. An in-place
// write to a shared socket object would make the two states compare equal and
// end the fixpoint one round early.
func TestCOW_MarkSocketsObservableIsolatedFromSharedClone(t *testing.T) {
	global := newState()
	id := allocID{site: 3}
	global.installObject(id, &object{kind: kindWebSocket})

	next := global.clone()
	markSocketsObservable(next)

	if global.heap[id].wsMaybeOpen {
		t.Fatal("markSocketsObservable mutated the shared previous global in place")
	}
	if !next.heap[id].wsMaybeOpen {
		t.Fatal("markSocketsObservable did not mark the published state")
	}
	if stateEqual(next, global) {
		t.Fatal("states must differ after marking, or the fixpoint ends early")
	}
}

func TestCOW_RewriteAllocIsolatedFromClone(t *testing.T) {
	st := newState()
	v := &js.Var{Data: []byte("y"), Decl: js.VariableDecl}
	from := allocID{site: 5}
	holder := allocID{site: 6}
	st.installObject(from, &object{})
	ho := &object{}
	ho.setNamed("ref", value{allocs: allocSet{{id: from}: true}, allocOnly: true}, true)
	st.installObject(holder, ho)
	st.setEnv(v, value{allocs: allocSet{{id: from}: true}, allocOnly: true})

	sibling := st.clone()
	to := allocID{site: 5, summary: true}
	st.ownHeap()
	st.heap[to] = st.heap[from]
	delete(st.heap, from)
	rewriteAlloc(st, from, to)

	if !hasAllocID(sibling.env[v].allocs, from) {
		t.Errorf("rewriteAlloc leaked env rewrite into sibling: %+v", sibling.env[v].allocs)
	}
	if got := sibling.heap[holder].fields["ref"]; !hasAllocID(got.allocs, from) {
		t.Errorf("rewriteAlloc leaked object rewrite into sibling: %+v", got.allocs)
	}
	if hasAllocID(st.env[v].allocs, from) {
		t.Errorf("rewriteAlloc did not rewrite the owning state env: %+v", st.env[v].allocs)
	}
	if got := st.heap[holder].fields["ref"]; hasAllocID(got.allocs, from) {
		t.Errorf("rewriteAlloc did not rewrite the owning state heap: %+v", got.allocs)
	}
}

func TestCOW_ResetAllocRefDepthIsolatedFromClone(t *testing.T) {
	st := newState()
	v := &js.Var{Data: []byte("z"), Decl: js.VariableDecl}
	id := allocID{site: 9}
	st.installObject(id, &object{})
	deep := value{allocs: allocSet{{id: id, minDepth: 1}: true}, allocOnly: true}
	st.setEnv(v, deep)

	sibling := st.clone()
	resetAllocRefDepth(st, map[allocID]bool{id: true})

	if !allocsEqual(sibling.env[v].allocs, deep.allocs) {
		t.Errorf("resetAllocRefDepth leaked into sibling: %+v", sibling.env[v].allocs)
	}
	if allocsEqual(st.env[v].allocs, deep.allocs) {
		t.Errorf("resetAllocRefDepth did not reset the owning state: %+v", st.env[v].allocs)
	}
}
