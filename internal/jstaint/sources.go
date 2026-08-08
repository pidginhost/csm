package jstaint

import (
	"bytes"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

// isKeyboardProp reports whether name is an event property whose value is a
// keystroke. e.target is deliberately absent: its .value is the input's current
// text, which legitimate search-as-you-type widgets read and post.
func isKeyboardProp(name []byte) bool {
	return bytes.Equal(name, []byte("key")) ||
		bytes.Equal(name, []byte("keyCode")) ||
		bytes.Equal(name, []byte("charCode")) ||
		bytes.Equal(name, []byte("which")) ||
		bytes.Equal(name, []byte("code"))
}

// The only member accesses allowed between the event variable and a keyboard
// property are these framework wrappers, for example e.originalEvent.key.
func isEventWrapperProp(name []byte) bool {
	return bytes.Equal(name, []byte("originalEvent")) ||
		bytes.Equal(name, []byte("nativeEvent"))
}

// keyboardSource reports whether expr statically reads a keyboard property off
// the handler's event variable, possibly through originalEvent/nativeEvent
// wrappers, and returns a dotted display string for evidence. The boolean result
// of a comparison is not handled here; barriers are enforced during propagation.
func keyboardSource(expr js.IExpr, eventVar *js.Var) (string, bool) {
	name, base, ok := memberAccessBytes(expr)
	if !ok || !isKeyboardProp(name) {
		return "", false
	}
	if !resolvesToEventBase(base, eventVar) {
		return "", false
	}
	return memberDisplay(expr), true
}

// resolvesToEventBase reports whether base is the event variable itself or a
// wrapper chain rooted at it.
func resolvesToEventBase(base js.IExpr, eventVar *js.Var) bool {
	if eventVar == nil {
		return false
	}
	return eventBaseVar(base) == canonicalVar(eventVar)
}

// eventBaseVar returns the canonical event-variable candidate at the root of a
// supported wrapper chain.
func eventBaseVar(base js.IExpr) *js.Var {
	for {
		base = ungroupExpr(base)
		if v, ok := base.(*js.Var); ok {
			return canonicalVar(v)
		}
		name, inner, ok := memberAccessBytes(base)
		if !ok || !isEventWrapperProp(name) {
			return nil
		}
		base = inner
	}
}

// memberAccess splits a dot or static-bracket member access into its property
// name and base expression.
func memberAccess(expr js.IExpr) (name string, base js.IExpr, ok bool) {
	data, base, ok := memberAccessBytes(expr)
	if !ok {
		return "", nil, false
	}
	return string(data), base, true
}

func memberAccessBytes(expr js.IExpr) (name []byte, base js.IExpr, ok bool) {
	switch e := ungroupExpr(expr).(type) {
	case *js.DotExpr:
		if n, ok := staticBytesOrIdent(ungroupExpr(e.Y)); ok {
			return n, e.X, true
		}
	case *js.IndexExpr:
		if n, ok := staticBytesOrIdent(ungroupExpr(e.Y)); ok {
			return n, e.X, true
		}
	}
	return nil, nil, false
}

// memberDisplay renders a member-access chain as dotted names for evidence,
// normalizing bracket access to dot form. An unresolvable base is shown as "?".
func memberDisplay(expr js.IExpr) string {
	var names [][]byte
	for {
		expr = ungroupExpr(expr)
		if v, ok := expr.(*js.Var); ok {
			return joinMemberDisplay(v.Name(), names)
		}
		name, base, ok := memberAccessBytes(expr)
		if !ok {
			return joinMemberDisplay([]byte("?"), names)
		}
		names = append(names, name)
		expr = base
	}
}

func joinMemberDisplay(base []byte, reversedNames [][]byte) string {
	size := len(base)
	for _, name := range reversedNames {
		size += 1 + len(name)
	}
	var display strings.Builder
	display.Grow(size)
	display.Write(base)
	for i := len(reversedNames) - 1; i >= 0; i-- {
		display.WriteByte('.')
		display.Write(reversedNames[i])
	}
	return display.String()
}

// binaryOpPropagates reports whether a binary operator's result carries taint
// from its operands. Comparisons are barriers because their boolean result does
// not contain the captured key; logical operators propagate because JavaScript
// returns one of the operand values.
func binaryOpPropagates(op js.TokenType) bool {
	switch op {
	case js.AddToken, js.SubToken, js.MulToken, js.DivToken, js.ModToken, js.ExpToken,
		js.LtLtToken, js.GtGtToken, js.GtGtGtToken,
		js.BitAndToken, js.BitOrToken, js.BitXorToken,
		js.AndToken, js.OrToken, js.NullishToken:
		return true
	default:
		return false
	}
}

// unaryOpPropagates reports whether a unary operator's result carries taint.
// !, typeof, void, and delete are barriers; +, -, ~, increment/decrement, and
// await keep a value derived from the operand.
func unaryOpPropagates(op js.TokenType) bool {
	switch op {
	case js.PosToken, js.NegToken, js.BitNotToken, js.AwaitToken,
		js.PreIncrToken, js.PreDecrToken, js.PostIncrToken, js.PostDecrToken:
		return true
	default:
		return false
	}
}
