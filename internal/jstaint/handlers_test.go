package jstaint

import (
	"testing"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

func discover(t *testing.T, src string) []handlerSite {
	t.Helper()
	ast, err := js.Parse(parse.NewInputBytes([]byte(src)), js.Options{})
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	return discoverHandlers(ast)
}

func TestDiscoverHandlers_AllRegistrationForms(t *testing.T) {
	cases := map[string]string{
		"on-property":         `document.onkeydown=function(e){e;};`,
		"bracket on-property":  `document["onkeypress"]=function(e){e;};`,
		"addEventListener":     `el.addEventListener("keyup",function(e){e;});`,
		"bare addEventListener": `addEventListener("keydown",function(e){e;});`,
		"react object prop":     `var o={onKeyDown:function(e){e;}};`,
		"arrow handler":         `document.onkeydown=(e)=>e;`,
		"identifier to decl":    `function h(e){e;}document.onkeydown=h;`,
		"identifier to var arrow": `var h=(e)=>e;el.addEventListener("keydown",h);`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			sites := discover(t, src)
			if len(sites) != 1 {
				t.Fatalf("discovered %d handlers, want 1", len(sites))
			}
			if sites[0].eventVar == nil {
				t.Fatalf("handler event variable is nil, want the first parameter")
			}
			if got := string(sites[0].eventVar.Name()); got != "e" {
				t.Errorf("event variable = %q, want %q", got, "e")
			}
		})
	}
}

func TestDiscoverHandlers_NonKeyRegistrationsIgnored(t *testing.T) {
	cases := map[string]string{
		"click listener":    `el.addEventListener("click",function(e){e;});`,
		"onclick property":   `el.onclick=function(e){e;};`,
		"input listener":     `el.addEventListener("input",function(e){e;});`,
		"lowercase react key": `var o={onkeydown:function(e){e;}};`,
		"method call value":   `el.addEventListener("keydown",this.handleKey);`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if sites := discover(t, src); len(sites) != 0 {
				t.Errorf("discovered %d handlers, want 0", len(sites))
			}
		})
	}
}

func TestDiscoverHandlers_GeneratorExcluded(t *testing.T) {
	if sites := discover(t, `document.onkeydown=function*(e){yield e;};`); len(sites) != 0 {
		t.Errorf("discovered %d handlers for a generator, want 0", len(sites))
	}
}

func TestDiscoverHandlers_ShadowedGlobalAddEventListenerExcluded(t *testing.T) {
	// A local addEventListener is not the DOM global, so the bare call form must
	// not be treated as a handler registration.
	src := `function addEventListener(t,f){f;}addEventListener("keydown",function(e){e;});`
	if sites := discover(t, src); len(sites) != 0 {
		t.Errorf("discovered %d handlers through a shadowed addEventListener, want 0", len(sites))
	}
}

func TestDiscoverHandlers_DestructuredFirstParamHasNoEventVar(t *testing.T) {
	// A destructured first parameter is outside version 1: it is discovered as a
	// registration but yields no plain-identifier event variable.
	sites := discover(t, `document.onkeydown=function({key}){key;};`)
	if len(sites) != 1 {
		t.Fatalf("discovered %d handlers, want 1", len(sites))
	}
	if sites[0].eventVar != nil {
		t.Errorf("event variable = %q, want nil for a destructured parameter", sites[0].eventVar.Name())
	}
}

func TestDiscoverHandlers_MultipleResolvedFunctionsAreUnioned(t *testing.T) {
	// When a handler identifier has more than one possible function value, each
	// resolved function is analyzed.
	src := `var h=function(e){e;};h=function(e2){e2;};document.onkeydown=h;`
	sites := discover(t, src)
	if len(sites) != 2 {
		t.Fatalf("discovered %d handler functions, want 2 (union of resolved values)", len(sites))
	}
}
