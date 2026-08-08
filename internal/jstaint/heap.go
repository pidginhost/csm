package jstaint

import (
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

// allocID identifies one abstract allocation instance: a deterministic source
// site plus a recency class. The two classes per site are the current instance
// and a summary of older instances, so the analyzer never invents an unbounded
// runtime-object identity.
type allocID struct {
	site    int
	summary bool
}

// allocRef carries the call depth of the path through which an allocation was
// obtained. Heap objects remain keyed by allocation identity.
type allocRef struct {
	id       allocID
	minDepth uint8
	advance  uint8
}

type allocSet map[allocRef]bool

// value is an abstract value at a program point: scalar taint carried directly
// plus the set of allocation instances the value may reference. Network sinks
// consume only the scalar part, because a URL, body, or header must be a string;
// an object reaches a sink only after a modeled serializer turns its reachable
// field taint into scalar taint.
type value struct {
	scalar taintSet
	allocs allocSet
	// allocOnly is true only when every represented runtime alternative is an
	// allocation. A branch that may instead produce an untracked clean primitive
	// clears it, preventing an object spread or cycle check from acting definite.
	allocOnly bool
	// scheme is the URL scheme this value definitely carries when used as a
	// destination, independent of taint. It gates whether a tainted URL is a
	// network sink.
	scheme schemeState
}

// object is the abstract contents of one allocation: statically named fields, an
// array-element field, and a wildcard field for writes whose key is not
// statically known.
type object struct {
	fields   map[string]value
	must     map[string]bool
	elem     value
	wild     value
	wildReq  value
	elemMay  bool
	wildMay  bool
	elemMust bool
	wildMust bool
	array    bool
	// Receiver provenance for network-sink method calls. kind names the platform
	// object this allocation represents; a generic object is never a sink.
	kind objectKind
	// XMLHttpRequest path state: whether an open has been seen on this path, and
	// the taint remembered from that open's URL and any setRequestHeader values.
	xhrOpened bool
	xhrURL    taintSet
	xhrHeader taintSet
	// WebSocket path state: possibly open once a later callback can observe it,
	// definitely closed only when closed on every merged path.
	wsMaybeOpen bool
	wsClosed    bool
}

func (o *object) clone() *object {
	n := &object{
		elem:        o.elem,
		wild:        o.wild,
		wildReq:     o.wildReq,
		elemMay:     o.elemMay,
		wildMay:     o.wildMay,
		elemMust:    o.elemMust,
		wildMust:    o.wildMust,
		array:       o.array,
		kind:        o.kind,
		xhrOpened:   o.xhrOpened,
		xhrURL:      o.xhrURL,
		xhrHeader:   o.xhrHeader,
		wsMaybeOpen: o.wsMaybeOpen,
		wsClosed:    o.wsClosed,
	}
	if len(o.fields) != 0 {
		n.fields = make(map[string]value, len(o.fields))
		for k, v := range o.fields {
			n.fields[k] = v
		}
	}
	if len(o.must) != 0 {
		n.must = make(map[string]bool, len(o.must))
		for k := range o.must {
			n.must[k] = true
		}
	}
	return n
}

// state is the flow-sensitive abstract store at a program point: per-variable
// values and the heap of allocation contents. Branch forks clone it; merges
// union it; loop fixed points compare it.
type state struct {
	env       map[*js.Var]value
	heap      map[allocID]*object
	continues bool
}

func newState() *state {
	return &state{env: map[*js.Var]value{}, heap: map[allocID]*object{}, continues: true}
}

func (s *state) clone() *state {
	n := &state{
		env:       make(map[*js.Var]value, len(s.env)),
		heap:      make(map[allocID]*object, len(s.heap)),
		continues: s.continues,
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
	s.continues = src.continues
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
	return value{
		scalar:    mergeTaint(a.scalar, b.scalar),
		allocs:    mergeAllocs(a.allocs, b.allocs),
		allocOnly: a.allocOnly && b.allocOnly,
		scheme:    mergeScheme(a.scheme, b.scheme),
	}
}

// advanceCallValue moves a value across one user-defined call edge. Facts past
// depth 1 are discarded. Allocation identities remain available at a blocked
// depth so the callee can still apply object mutations without propagating taint.
func advanceCallValue(v value) value {
	v.scalar = applyTaintDepth(v.scalar, 0, 1)
	if len(v.allocs) != 0 {
		refs := make(allocSet, len(v.allocs))
		for ref := range v.allocs {
			if ref.advance < 2 {
				ref.advance++
			}
			refs[ref] = true
		}
		v.allocs = refs
	}
	return v
}

// returnValueAtDepthOne materializes the lazy allocation constraints accumulated
// while a depth-1 callee used an argument, then records the return edge without
// counting the same call twice.
func returnValueAtDepthOne(v value) value {
	v.scalar = applyTaintDepth(v.scalar, 1, 0)
	if len(v.allocs) == 0 {
		return v
	}
	refs := make(allocSet, len(v.allocs))
	for ref := range v.allocs {
		refs[composeAllocRef(ref, allocRef{minDepth: 1})] = true
	}
	v.allocs = refs
	return v
}

func applyRefDepth(v value, parent allocRef) value {
	v.scalar = applyTaintDepth(v.scalar, parent.minDepth, parent.advance)
	if len(v.allocs) != 0 && (parent.minDepth != 0 || parent.advance != 0) {
		refs := make(allocSet, len(v.allocs))
		for ref := range v.allocs {
			refs[composeAllocRef(ref, parent)] = true
		}
		v.allocs = refs
	}
	return v
}

// composeAllocRef applies parent after child. Each constraint represents
// max(depth, minDepth) + advance, so a later minimum is discounted by an
// advance the child has already applied.
func composeAllocRef(child, parent allocRef) allocRef {
	requiredMin := uint8(0)
	if parent.minDepth > child.advance {
		requiredMin = parent.minDepth - child.advance
	}
	if child.minDepth < requiredMin {
		child.minDepth = requiredMin
	}
	child.advance += parent.advance
	if child.advance > 2 {
		child.advance = 2
	}
	return child
}

func applyTaintDepth(ts taintSet, minDepth, advance uint8) taintSet {
	if len(ts) == 0 || (minDepth == 0 && advance == 0) {
		return ts
	}
	out := make(taintSet, len(ts))
	for fact, chain := range ts {
		if fact.callDepth < minDepth {
			fact.callDepth = minDepth
		}
		fact.callDepth += advance
		if fact.callDepth <= 1 {
			if existing, ok := out[fact]; !ok || shorterChain(chain, existing) {
				out[fact] = chain
			}
		}
	}
	return out
}

func mergePresentValue(current value, present bool, next value) (value, bool) {
	if !present {
		return next, true
	}
	return mergeValue(current, next), true
}

func mergeObject(a, b *object) *object {
	n := &object{
		elemMay:  a.elemMay || b.elemMay,
		wildMay:  a.wildMay || b.wildMay,
		elemMust: a.elemMust && b.elemMust,
		wildMust: a.wildMust && b.wildMust,
		array:    a.array,
		// The two operands are the same allocation site, so kind agrees; a fresh
		// generic instance from one path defers to the provenance of the other.
		kind:        mergeKind(a.kind, b.kind),
		xhrOpened:   a.xhrOpened || b.xhrOpened,
		xhrURL:      mergeTaint(a.xhrURL, b.xhrURL),
		xhrHeader:   mergeTaint(a.xhrHeader, b.xhrHeader),
		wsMaybeOpen: a.wsMaybeOpen || b.wsMaybeOpen,
		wsClosed:    a.wsClosed && b.wsClosed,
	}
	if a.elemMay {
		n.elem = a.elem
	}
	if b.elemMay {
		n.elem, _ = mergePresentValue(n.elem, a.elemMay, b.elem)
	}
	if a.wildMay {
		n.wild = a.wild
	}
	if b.wildMay {
		n.wild, _ = mergePresentValue(n.wild, a.wildMay, b.wild)
	}
	if n.wildMust {
		n.wildReq = mergeValue(a.wildReq, b.wildReq)
	}
	n.fields = make(map[string]value, len(a.fields)+len(b.fields))
	for k, v := range a.fields {
		if bv, ok := b.fields[k]; ok {
			n.fields[k] = mergeValue(v, bv)
		} else if b.wildMay {
			n.fields[k] = mergeValue(v, b.wild)
		} else {
			n.fields[k] = v
		}
	}
	for k, v := range b.fields {
		if _, ok := n.fields[k]; !ok {
			if a.wildMay {
				n.fields[k] = mergeValue(a.wild, v)
			} else {
				n.fields[k] = v
			}
		}
	}
	for k := range a.must {
		if b.must[k] {
			if n.must == nil {
				n.must = map[string]bool{}
			}
			n.must[k] = true
		}
	}
	return n
}

func mergeState(a, b *state) *state {
	if !a.continues && b.continues {
		return b.clone()
	}
	if a.continues && !b.continues {
		return a.clone()
	}
	n := &state{
		env:       make(map[*js.Var]value, len(a.env)+len(b.env)),
		heap:      make(map[allocID]*object, len(a.heap)+len(b.heap)),
		continues: a.continues || b.continues,
	}
	for k, v := range a.env {
		if bv, ok := b.env[k]; ok {
			n.env[k] = mergeValue(v, bv)
		} else {
			v.allocOnly = false
			n.env[k] = v
		}
	}
	for k, v := range b.env {
		if _, ok := n.env[k]; !ok {
			v.allocOnly = false
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
	return a.allocOnly == b.allocOnly && a.scheme == b.scheme &&
		taintEqual(a.scalar, b.scalar) && allocsEqual(a.allocs, b.allocs)
}

func objectEqual(a, b *object) bool {
	if a.array != b.array || a.elemMay != b.elemMay || a.wildMay != b.wildMay ||
		a.elemMust != b.elemMust || a.wildMust != b.wildMust ||
		a.kind != b.kind || a.xhrOpened != b.xhrOpened ||
		a.wsMaybeOpen != b.wsMaybeOpen || a.wsClosed != b.wsClosed ||
		!taintEqual(a.xhrURL, b.xhrURL) || !taintEqual(a.xhrHeader, b.xhrHeader) ||
		len(a.must) != len(b.must) || !valueEqual(a.elem, b.elem) ||
		!valueEqual(a.wildReq, b.wildReq) ||
		!valueEqual(a.wild, b.wild) || len(a.fields) != len(b.fields) {
		return false
	}
	for k := range a.must {
		if !b.must[k] {
			return false
		}
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
	if a.continues != b.continues || len(a.env) != len(b.env) || len(a.heap) != len(b.heap) {
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
		if isArrayIndexName(name) {
			return fieldKey{kind: fieldElem, name: name}
		}
		return fieldKey{kind: fieldNamed, name: name}
	}
	if name, ok := numericPropertyNameOf(key); ok {
		if isArrayIndexName(name) {
			return fieldKey{kind: fieldElem, name: name}
		}
		return fieldKey{kind: fieldNamed, name: name}
	}
	return fieldKey{kind: fieldWild}
}

func numericPropertyNameOf(expr js.IExpr) (string, bool) {
	negative := false
	for {
		u, ok := ungroupExpr(expr).(*js.UnaryExpr)
		if !ok || (u.Op != js.PosToken && u.Op != js.NegToken) {
			break
		}
		if u.Op == js.NegToken {
			negative = !negative
		}
		expr = u.X
	}
	lit, ok := ungroupExpr(expr).(*js.LiteralExpr)
	if !ok || (lit.TokenType != js.IntegerToken && lit.TokenType != js.DecimalToken) {
		return "", false
	}
	name := numericPropertyName(lit)
	if name == "" {
		return "", false
	}
	if negative && name != "0" {
		name = "-" + name
	}
	return name, true
}

func numericPropertyName(lit *js.LiteralExpr) string {
	raw := strings.ReplaceAll(string(lit.Data), "_", "")
	if strings.HasSuffix(raw, "n") {
		integer := new(big.Int)
		if _, ok := integer.SetString(strings.TrimSuffix(raw, "n"), 0); ok {
			return integer.String()
		}
		return ""
	}
	if lit.TokenType == js.IntegerToken {
		if n, err := strconv.ParseUint(raw, 0, 64); err == nil {
			return jsNumberPropertyName(float64(n))
		}
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsInf(n, 0) || math.IsNaN(n) {
		return ""
	}
	return jsNumberPropertyName(n)
}

func jsNumberPropertyName(n float64) string {
	if n == 0 {
		return "0"
	}
	abs := math.Abs(n)
	if abs >= 1e-6 && abs < 1e21 {
		return strconv.FormatFloat(n, 'f', -1, 64)
	}
	s := strconv.FormatFloat(n, 'e', -1, 64)
	parts := strings.SplitN(s, "e", 2)
	exponent, err := strconv.Atoi(parts[1])
	if err != nil {
		return ""
	}
	return parts[0] + "e" + fmtSignedExponent(exponent)
}

func fmtSignedExponent(exponent int) string {
	if exponent >= 0 {
		return "+" + strconv.Itoa(exponent)
	}
	return strconv.Itoa(exponent)
}

// isArrayIndexName reports whether a string is a canonical JavaScript array
// index. Bracket access coerces both 0 and "0" to the same property key.
func isArrayIndexName(name string) bool {
	if name == "" || (len(name) > 1 && name[0] == '0') {
		return false
	}
	for i := range name {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(name, 10, 32)
	return err == nil && n < 1<<32-1
}

// getField reads one field of an object. A static named read and a wildcard read
// both consume the wildcard, because a wildcard write may have set any property.
func getField(o *object, key fieldKey) (value, bool) {
	switch key.kind {
	case fieldNamed:
		if v, ok := o.fields[key.name]; ok {
			return v, o.must[key.name]
		}
		if o.wildMay {
			return o.wild, false
		}
		return value{}, false
	case fieldElem:
		if key.name != "" {
			if v, ok := o.fields[key.name]; ok {
				return v, o.must[key.name]
			}
		}
		var out value
		have := false
		if o.elemMay {
			out, have = mergePresentValue(out, have, o.elem)
		}
		if o.wildMay {
			out, _ = mergePresentValue(out, have, o.wild)
		}
		return out, false
	default:
		var out value
		have := false
		if o.elemMay {
			out, have = mergePresentValue(out, have, o.elem)
		}
		if o.wildMay {
			out, have = mergePresentValue(out, have, o.wild)
		}
		for _, fv := range o.fields {
			out, have = mergePresentValue(out, have, fv)
		}
		return out, false
	}
}

func (o *object) setNamed(name string, v value, strong bool) {
	if o.fields == nil {
		o.fields = map[string]value{}
	}
	if strong {
		o.fields[name] = v
		// A preceding wildcard write may have selected this exact property, so it
		// is no longer certain that an unresolved field remains after overwrite.
		o.wildMust = false
		o.wildReq = value{}
		if o.must == nil {
			o.must = map[string]bool{}
		}
		o.must[name] = true
	} else {
		if o.wildMust {
			// The weak write may select the required unresolved property. Preserve
			// both its old value and the overwrite as runtime alternatives.
			o.wildReq = mergeValue(o.wildReq, v)
		}
		old, ok := o.fields[name]
		if !ok {
			old = o.wild
		}
		o.fields[name] = mergeValue(old, v)
	}
}

func (o *object) deleteNamed(name string) {
	// The required unresolved property may be the deleted name. Other unresolved
	// properties remain possible, but none remains certain after this delete.
	o.wildMust = false
	o.wildReq = value{}
	if o.wildMay {
		// Keep a clean tombstone so the deleted property does not expose an older
		// unresolved write. A later wildcard write folds into the tombstone again.
		if o.fields == nil {
			o.fields = map[string]value{}
		}
		o.fields[name] = value{}
	} else {
		delete(o.fields, name)
	}
	delete(o.must, name)
}

func (o *object) weakElem(v value, definite bool) {
	o.elem, o.elemMay = mergePresentValue(o.elem, o.elemMay, v)
	if definite {
		o.elemMust = true
	}
}

// writeWild applies a write whose key is unresolved. Existing named fields must
// absorb it because the key may select any of them; a later strong named write
// can then replace that field without clearing the wildcard for other names.
func (o *object) writeWild(v value, definite bool) {
	o.wild, o.wildMay = mergePresentValue(o.wild, o.wildMay, v)
	if definite {
		o.wildMust = true
		o.wildReq = v
	} else if o.wildMust {
		o.wildReq = mergeValue(o.wildReq, v)
	}
	for k, fv := range o.fields {
		o.fields[k] = mergeValue(fv, v)
	}
}
