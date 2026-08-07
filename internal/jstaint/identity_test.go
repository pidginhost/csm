package jstaint

import (
	"testing"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// distinctCanonicalIdentities returns how many distinct canonical *js.Var the
// named variable resolves to across every occurrence in src. Shadowing yields
// more than one; a shared closure capture yields exactly one.
func distinctCanonicalIdentities(t *testing.T, src, name string) int {
	t.Helper()
	ast, err := js.Parse(parse.NewInputBytes([]byte(src)), js.Options{})
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	seen := map[*js.Var]bool{}
	c := &identityCollector{name: name, seen: seen}
	js.Walk(c, ast)
	return len(seen)
}

type identityCollector struct {
	name string
	seen map[*js.Var]bool
}

func (c *identityCollector) Enter(n js.INode) js.IVisitor {
	if v, ok := n.(*js.Var); ok && string(v.Name()) == c.name {
		c.seen[canonicalVar(v)] = true
	}
	return c
}

func (c *identityCollector) Exit(js.INode) {}

func TestCanonicalVar_ClosureCaptureSharesOneIdentity(t *testing.T) {
	src := `let buf="";document.onkeydown=function(e){buf=e.key;};` +
		`setInterval(function(){navigator.sendBeacon("/c",buf);},9);`
	if got := distinctCanonicalIdentities(t, src, "buf"); got != 1 {
		t.Errorf("closure-captured buf has %d canonical identities, want 1", got)
	}
}

func TestCanonicalVar_ShadowedNamesStaySeparate(t *testing.T) {
	src := `let a=1;function f(){let a=2;return a;}a;`
	if got := distinctCanonicalIdentities(t, src, "a"); got != 2 {
		t.Errorf("shadowed a has %d canonical identities, want 2", got)
	}
}

func TestCanonicalVar_UseBeforeDeclarationResolvesToDeclaration(t *testing.T) {
	// A use textually before the var declaration in the same function must share
	// the declaration's canonical identity once the parser links them.
	src := `function f(){use(x);var x=1;return x;}`
	if got := distinctCanonicalIdentities(t, src, "x"); got != 1 {
		t.Errorf("use-before-declaration x has %d canonical identities, want 1", got)
	}
}

func TestCanonicalVar_ModuleImportBindingIsOneIdentity(t *testing.T) {
	// ES module syntax must parse and the imported binding must resolve to one
	// canonical identity across its uses. goja cannot parse this at all.
	src := `import {send} from "./m.js";document.onkeyup=function(e){send(e.key);};`
	if got := distinctCanonicalIdentities(t, src, "send"); got != 1 {
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
	if ok && got == "key" {
		t.Errorf("staticStringOrIdent decoded an escape to %q; escapes are out of scope", got)
	}
}
