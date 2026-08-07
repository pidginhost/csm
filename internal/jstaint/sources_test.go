package jstaint

import (
	"testing"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// sourceOf evaluates keyboardSource on expr as if it appeared in the body of a
// keydown handler whose event parameter is named e.
func sourceOf(t *testing.T, expr string) (string, bool) {
	t.Helper()
	src := `document.onkeydown=function(e){var z=` + expr + `;z;};`
	ast, err := js.Parse(parse.NewInputBytes([]byte(src)), js.Options{})
	if err != nil {
		t.Fatalf("parse %q: %v", expr, err)
	}
	sites := discoverHandlers(ast)
	if len(sites) != 1 || sites[0].eventVar == nil {
		t.Fatalf("fixture did not yield one handler with an event var")
	}
	decl := sites[0].fn.body.List[0].(*js.VarDecl)
	return keyboardSource(decl.List[0].Default, sites[0].eventVar)
}

func TestKeyboardSource_Positives(t *testing.T) {
	cases := map[string]string{
		"e.key":                 "e.key",
		"e.keyCode":             "e.keyCode",
		"e.charCode":            "e.charCode",
		"e.which":               "e.which",
		"e.code":                "e.code",
		`e["key"]`:              "e.key",
		"e.originalEvent.key":   "e.originalEvent.key",
		"e.nativeEvent.which":   "e.nativeEvent.which",
		"e.originalEvent.nativeEvent.keyCode": "e.originalEvent.nativeEvent.keyCode",
	}
	for expr, want := range cases {
		t.Run(expr, func(t *testing.T) {
			got, ok := sourceOf(t, expr)
			if !ok {
				t.Fatalf("keyboardSource(%q) not recognized as a source", expr)
			}
			if got != want {
				t.Errorf("display = %q, want %q", got, want)
			}
		})
	}
}

func TestKeyboardSource_Negatives(t *testing.T) {
	exprs := []string{
		"e.target.value",           // input value, not a keystroke
		"e.target.dataset.key",     // arbitrary chain, not a wrapper
		"KeyCode.RETURN",           // base is not the event var
		"obj.which",                // base is not the event var
		"e.originalEvent.target.value", // wrapper then non-source
		"e.value",                  // not a keyboard property
		"e.target.key",             // target is not a known wrapper
	}
	for _, expr := range exprs {
		t.Run(expr, func(t *testing.T) {
			if got, ok := sourceOf(t, expr); ok {
				t.Errorf("keyboardSource(%q) = %q, want not-a-source", expr, got)
			}
		})
	}
}

func TestBinaryOpPropagates(t *testing.T) {
	propagate := []js.TokenType{js.AddToken, js.SubToken, js.MulToken, js.DivToken,
		js.ModToken, js.ExpToken, js.LtLtToken, js.GtGtToken, js.GtGtGtToken,
		js.BitAndToken, js.BitOrToken, js.BitXorToken, js.AndToken, js.OrToken, js.NullishToken}
	for _, op := range propagate {
		if !binaryOpPropagates(op) {
			t.Errorf("binaryOpPropagates(%s) = false, want true", op)
		}
	}
	barriers := []js.TokenType{js.EqEqToken, js.EqEqEqToken, js.NotEqToken, js.NotEqEqToken,
		js.LtToken, js.LtEqToken, js.GtToken, js.GtEqToken, js.InToken, js.InstanceofToken}
	for _, op := range barriers {
		if binaryOpPropagates(op) {
			t.Errorf("binaryOpPropagates(%s) = true, want false (comparison barrier)", op)
		}
	}
}

func TestUnaryOpPropagates(t *testing.T) {
	for _, op := range []js.TokenType{js.PosToken, js.NegToken, js.BitNotToken,
		js.PreIncrToken, js.PreDecrToken, js.PostIncrToken, js.PostDecrToken} {
		if !unaryOpPropagates(op) {
			t.Errorf("unaryOpPropagates(%s) = false, want true", op)
		}
	}
	for _, op := range []js.TokenType{js.NotToken, js.TypeofToken, js.VoidToken, js.DeleteToken} {
		if unaryOpPropagates(op) {
			t.Errorf("unaryOpPropagates(%s) = true, want false (barrier)", op)
		}
	}
}
