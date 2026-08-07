package jstaint

import "github.com/tdewolff/parse/v2/js"

// canonicalVar follows the parser's Link chain to the declaration identity. The
// parser sets Link when it merges an undeclared use with its later declaration
// or an outer-scope binding, so following it to the end yields one stable
// identity per variable. Shadowed declarations keep distinct identities because
// each is its own declared Var with a nil Link.
func canonicalVar(v *js.Var) *js.Var {
	for v.Link != nil {
		v = v.Link
	}
	return v
}

// staticStringOrIdent returns the literal identifier or string value of expr, if
// expr is a literal. It accepts both concrete literal forms the AST uses: a
// DotExpr member name arrives as a LiteralExpr value, while a bracket index or
// call argument arrives as a *LiteralExpr pointer. Handling only the pointer
// form would silently drop every dotted member name.
//
// String tokens are unquoted but not unescaped: escape spellings such as
// \x6b are out of version 1 scope, so the raw bytes between the quotes are
// returned verbatim.
func staticStringOrIdent(expr js.IExpr) (string, bool) {
	data, ok := staticBytesOrIdent(expr)
	if !ok {
		return "", false
	}
	return string(data), true
}

// staticBytesOrIdent is the allocation-free form of staticStringOrIdent for
// AST walkers that only need to compare or render the literal bytes.
func staticBytesOrIdent(expr js.IExpr) ([]byte, bool) {
	switch lit := expr.(type) {
	case *js.LiteralExpr:
		return literalBytes(lit.TokenType, lit.Data)
	case js.LiteralExpr:
		return literalBytes(lit.TokenType, lit.Data)
	default:
		return nil, false
	}
}

func literalText(tt js.TokenType, data []byte) (string, bool) {
	literal, ok := literalBytes(tt, data)
	if !ok {
		return "", false
	}
	return string(literal), true
}

func literalBytes(tt js.TokenType, data []byte) ([]byte, bool) {
	switch tt {
	case js.IdentifierToken:
		return data, true
	case js.StringToken:
		if len(data) < 2 {
			return nil, false
		}
		q := data[0]
		if (q != '\'' && q != '"') || data[len(data)-1] != q {
			return nil, false
		}
		return data[1 : len(data)-1], true
	default:
		return nil, false
	}
}
