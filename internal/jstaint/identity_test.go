package jstaint

import (
	"testing"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// collectedIdentities reports the raw and canonical variable pointers for each
// occurrence of name. A closure fixture needs both sets so it can prove that
// canonicalVar actually followed a parser Link instead of passing because the
// parser happened to reuse one pointer everywhere.
func collectedIdentities(t *testing.T, src, name string) (map[*js.Var]bool, map[*js.Var]bool) {
	t.Helper()
	ast, err := js.Parse(parse.NewInputBytes([]byte(src)), js.Options{})
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	raw := map[*js.Var]bool{}
	canonical := map[*js.Var]bool{}
	c := &identityCollector{name: name, raw: raw, canonical: canonical}
	js.Walk(c, ast)
	return raw, canonical
}

type identityCollector struct {
	name      string
	raw       map[*js.Var]bool
	canonical map[*js.Var]bool
}

func (c *identityCollector) Enter(n js.INode) js.IVisitor {
	if v, ok := n.(*js.Var); ok && string(v.Name()) == c.name {
		c.raw[v] = true
		c.canonical[canonicalVar(v)] = true
	}
	return c
}

func (c *identityCollector) Exit(js.INode) {}

func TestCanonicalVar_ClosureCaptureSharesOneIdentity(t *testing.T) {
	src := `let buf="";document.onkeydown=function(e){buf=e.key;};` +
		`setInterval(function(){navigator.sendBeacon("/c",buf);},9);`
	raw, canonical := collectedIdentities(t, src, "buf")
	if len(raw) <= 1 {
		t.Fatalf("parser produced %d raw buf identity; fixture did not exercise a Link", len(raw))
	}
	if got := len(canonical); got != 1 {
		t.Errorf("closure-captured buf has %d canonical identities, want 1", got)
	}
}

func TestCanonicalVar_ShadowedNamesStaySeparate(t *testing.T) {
	src := `let a=1;function f(){let a=2;return a;}a;`
	_, canonical := collectedIdentities(t, src, "a")
	if got := len(canonical); got != 2 {
		t.Errorf("shadowed a has %d canonical identities, want 2", got)
	}
}

func TestCanonicalVar_UseBeforeDeclarationResolvesToDeclaration(t *testing.T) {
	// A use textually before the var declaration in the same function must share
	// the declaration's canonical identity whether the parser reuses or links it.
	src := `function f(){use(x);var x=1;return x;}`
	_, canonical := collectedIdentities(t, src, "x")
	if got := len(canonical); got != 1 {
		t.Errorf("use-before-declaration x has %d canonical identities, want 1", got)
	}
}

func TestCanonicalVar_ModuleImportBindingIsOneIdentity(t *testing.T) {
	// ES module syntax must parse and the imported binding must resolve to one
	// canonical identity across its uses. goja cannot parse this at all.
	src := `import {send} from "./m.js";document.onkeyup=function(e){send(e.key);};`
	_, canonical := collectedIdentities(t, src, "send")
	if got := len(canonical); got != 1 {
		t.Errorf("module import send has %d canonical identities, want 1", got)
	}
}

func TestStaticStringOrIdent_AcceptsBothLiteralForms(t *testing.T) {
	// DotExpr.Y is a LiteralExpr value; a bracket/arg string literal is a
	// *LiteralExpr pointer. A helper that handles only the pointer form would
	// silently fail to read dotted member names, disabling the whole detector.
	cases := []struct {
		name string
		expr js.IExpr
		want string
	}{
		{"dot member value form", js.LiteralExpr{TokenType: js.IdentifierToken, Data: []byte("key")}, "key"},
		{"bracket string pointer form", &js.LiteralExpr{TokenType: js.StringToken, Data: []byte(`"key"`)}, "key"},
		{"single-quoted pointer form", &js.LiteralExpr{TokenType: js.StringToken, Data: []byte(`'keydown'`)}, "keydown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := staticStringOrIdent(tc.expr)
			if !ok || got != tc.want {
				t.Errorf("staticStringOrIdent = (%q,%t), want (%q,true)", got, ok, tc.want)
			}
		})
	}
}

func TestStaticStringOrIdent_DoesNotDecodeEscapes(t *testing.T) {
	// Escape spellings are explicitly out of version 1 scope: the matcher works
	// on literal ASCII bytes, so an escaped "key" must not resolve to key.
	got, ok := staticStringOrIdent(&js.LiteralExpr{TokenType: js.StringToken, Data: []byte(`"\x6bey"`)})
	if !ok || got != `\x6bey` {
		t.Errorf("staticStringOrIdent = (%q,%t), want (%q,true)", got, ok, `\x6bey`)
	}
}

func TestStaticStringOrIdent_RejectsNonStringLiterals(t *testing.T) {
	cases := []js.LiteralExpr{
		{TokenType: js.IntegerToken, Data: []byte("1")},
		{TokenType: js.TrueToken, Data: []byte("true")},
		{TokenType: js.StringToken, Data: []byte(`"unterminated`)},
		{TokenType: js.StringToken, Data: []byte(`'mismatched"`)},
	}
	for _, lit := range cases {
		if got, ok := staticStringOrIdent(&lit); ok || got != "" {
			t.Errorf("staticStringOrIdent(%s) = (%q,%t), want (\"\",false)", lit.Data, got, ok)
		}
	}
}
