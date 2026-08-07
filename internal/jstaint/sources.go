package jstaint

import "github.com/tdewolff/parse/v2/js"

// keyboardProps are the event properties whose value is a keystroke. e.target is
// deliberately absent: its .value is the input's current text, which legitimate
// search-as-you-type widgets read and post.
func isKeyboardProp(name string) bool {
	switch name {
	case "key", "keyCode", "charCode", "which", "code":
		return true
	default:
		return false
	}
}

// The only member accesses allowed between the event variable and a keyboard
// property are these framework wrappers, for example e.originalEvent.key.
func isEventWrapperProp(name string) bool {
	switch name {
	case "originalEvent", "nativeEvent":
		return true
	default:
		return false
	}
}

// keyboardSource reports whether expr statically reads a keyboard property off
// the handler's event variable, possibly through originalEvent/nativeEvent
// wrappers, and returns a dotted display string for evidence. The boolean result
// of a comparison is not handled here; barriers are enforced during propagation.
func keyboardSource(expr js.IExpr, eventVar *js.Var) (string, bool) {
	name, base, ok := memberAccess(expr)
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
	base = ungroupExpr(base)
	if v, ok := base.(*js.Var); ok {
		return canonicalVar(v) == eventVar
	}
	name, inner, ok := memberAccess(base)
	if !ok || !isEventWrapperProp(name) {
		return false
	}
	return resolvesToEventBase(inner, eventVar)
}

// memberAccess splits a dot or static-bracket member access into its property
// name and base expression.
func memberAccess(expr js.IExpr) (name string, base js.IExpr, ok bool) {
	switch e := ungroupExpr(expr).(type) {
	case *js.DotExpr:
		if n, ok := staticStringOrIdent(ungroupExpr(e.Y)); ok {
			return n, e.X, true
		}
	case *js.IndexExpr:
		if n, ok := staticStringOrIdent(ungroupExpr(e.Y)); ok {
			return n, e.X, true
		}
	}
	return "", nil, false
}

// memberDisplay renders a member-access chain as dotted names for evidence,
// normalizing bracket access to dot form. An unresolvable base is shown as "?".
func memberDisplay(expr js.IExpr) string {
	expr = ungroupExpr(expr)
	if v, ok := expr.(*js.Var); ok {
		return string(v.Name())
	}
	name, base, ok := memberAccess(expr)
	if !ok {
		return "?"
	}
	return memberDisplay(base) + "." + name
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
// !, typeof, void, and delete are barriers; +, -, ~, and increment/decrement
// keep a value derived from the operand.
func unaryOpPropagates(op js.TokenType) bool {
	switch op {
	case js.PosToken, js.NegToken, js.BitNotToken,
		js.PreIncrToken, js.PreDecrToken, js.PostIncrToken, js.PostDecrToken:
		return true
	default:
		return false
	}
}
