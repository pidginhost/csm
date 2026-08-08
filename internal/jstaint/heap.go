package jstaint

import "github.com/tdewolff/parse/v2/js"

// elemField is the synthetic field name that holds array element taint. Array
// element writes and reads all funnel through it, so an object and an array can
// share the object model without a separate array representation.
const elemField = "@elem"

// allocID identifies one abstract allocation instance: a deterministic source
// site plus a recency class. The two classes per site are the current instance
// and a summary of older instances, so the analyzer never invents an unbounded
// runtime-object identity.
type allocID struct {
	site    int
	summary bool
}

type allocSet map[allocID]bool

// value is an abstract value at a program point: scalar taint carried directly
// plus the set of allocation instances the value may reference. Network sinks
// consume only the scalar part, because a URL, body, or header must be a string;
// an object reaches a sink only after a modeled serializer turns its reachable
// field taint into scalar taint.
type value struct {
	scalar taintSet
	allocs allocSet
}

func (v value) isEmpty() bool {
	return len(v.scalar) == 0 && len(v.allocs) == 0
}

// object is the abstract contents of one allocation: statically named fields, an
// array-element field, and a wildcard field for writes whose key is not
// statically known.
type object struct {
	fields map[string]value
	wild   value
}

func (o *object) clone() *object {
	n := &object{wild: o.wild}
	if len(o.fields) != 0 {
		n.fields = make(map[string]value, len(o.fields))
		for k, v := range o.fields {
			n.fields[k] = v
		}
	}
	return n
}

// state is the flow-sensitive abstract store at a program point: per-variable
// values and the heap of allocation contents. Branch forks clone it; merges
// union it; loop fixed points compare it.
type state struct {
	env  map[*js.Var]value
	heap map[allocID]*object
}

func newState() *state {
	return &state{env: map[*js.Var]value{}, heap: map[allocID]*object{}}
}

func (s *state) clone() *state {
	n := &state{
		env:  make(map[*js.Var]value, len(s.env)),
		heap: make(map[allocID]*object, len(s.heap)),
	}
	for k, v := range s.env {
		n.env[k] = v
	}
	for k, o := range s.heap {
		n.heap[k] = o.clone()
	}
	return n
}

// replaceWith overwrites s in place with the contents of src. It lets callers
// keep a stable *state identity across a may-execute merge.
func (s *state) replaceWith(src *state) {
	for k := range s.env {
		delete(s.env, k)
	}
	for k := range s.heap {
		delete(s.heap, k)
	}
	for k, v := range src.env {
		s.env[k] = v
	}
	for k, o := range src.heap {
		s.heap[k] = o
	}
}

func mergeAllocs(a, b allocSet) allocSet {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	out := make(allocSet, len(a)+len(b))
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func mergeValue(a, b value) value {
	return value{scalar: mergeTaint(a.scalar, b.scalar), allocs: mergeAllocs(a.allocs, b.allocs)}
}

func mergeObject(a, b *object) *object {
	n := &object{wild: mergeValue(a.wild, b.wild)}
	n.fields = make(map[string]value, len(a.fields)+len(b.fields))
	for k, v := range a.fields {
		n.fields[k] = v
	}
	for k, v := range b.fields {
		if ex, ok := n.fields[k]; ok {
			n.fields[k] = mergeValue(ex, v)
		} else {
			n.fields[k] = v
		}
	}
	return n
}

func mergeState(a, b *state) *state {
	n := &state{
		env:  make(map[*js.Var]value, len(a.env)+len(b.env)),
		heap: make(map[allocID]*object, len(a.heap)+len(b.heap)),
	}
	for k, v := range a.env {
		n.env[k] = v
	}
	for k, v := range b.env {
		if ex, ok := n.env[k]; ok {
			n.env[k] = mergeValue(ex, v)
		} else {
			n.env[k] = v
		}
	}
	for k, o := range a.heap {
		n.heap[k] = o.clone()
	}
	for k, o := range b.heap {
		if ex, ok := n.heap[k]; ok {
			n.heap[k] = mergeObject(ex, o)
		} else {
			n.heap[k] = o.clone()
		}
	}
	return n
}

func allocsEqual(a, b allocSet) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func valueEqual(a, b value) bool {
	return taintEqual(a.scalar, b.scalar) && allocsEqual(a.allocs, b.allocs)
}

func objectEqual(a, b *object) bool {
	if !valueEqual(a.wild, b.wild) || len(a.fields) != len(b.fields) {
		return false
	}
	for k, va := range a.fields {
		vb, ok := b.fields[k]
		if !ok || !valueEqual(va, vb) {
			return false
		}
	}
	return true
}

func stateEqual(a, b *state) bool {
	if len(a.env) != len(b.env) || len(a.heap) != len(b.heap) {
		return false
	}
	for k, va := range a.env {
		vb, ok := b.env[k]
		if !ok || !valueEqual(va, vb) {
			return false
		}
	}
	for k, oa := range a.heap {
		ob, ok := b.heap[k]
		if !ok || !objectEqual(oa, ob) {
			return false
		}
	}
	return true
}

// fieldKind selects which slot of an object a member access reaches.
type fieldKind uint8

const (
	fieldNamed fieldKind = iota
	fieldElem
	fieldWild
)

type fieldKey struct {
	kind fieldKind
	name string
}

// fieldKeyOf classifies a member-access key expression. A static string or
// identifier names a field, a numeric literal index is an array element, and an
// unresolved computed key is the wildcard.
func fieldKeyOf(key js.IExpr) fieldKey {
	key = ungroupExpr(key)
	if name, ok := staticStringOrIdent(key); ok {
		return fieldKey{kind: fieldNamed, name: name}
	}
	if lit, ok := key.(*js.LiteralExpr); ok {
		if lit.TokenType == js.IntegerToken || lit.TokenType == js.DecimalToken {
			return fieldKey{kind: fieldElem}
		}
	}
	return fieldKey{kind: fieldWild}
}

// getField reads one field of an object. A static named read and a wildcard read
// both consume the wildcard, because a wildcard write may have set any property.
func getField(o *object, key fieldKey) value {
	switch key.kind {
	case fieldNamed:
		return mergeValue(o.fields[key.name], o.wild)
	case fieldElem:
		return mergeValue(o.fields[elemField], o.wild)
	default:
		return mergeValue(o.fields[elemField], o.wild)
	}
}

func (o *object) setNamed(name string, v value, strong bool) {
	if o.fields == nil {
		o.fields = map[string]value{}
	}
	if strong {
		o.fields[name] = v
	} else {
		o.fields[name] = mergeValue(o.fields[name], v)
	}
}

func (o *object) weakElem(v value) {
	if o.fields == nil {
		o.fields = map[string]value{}
	}
	o.fields[elemField] = mergeValue(o.fields[elemField], v)
}
