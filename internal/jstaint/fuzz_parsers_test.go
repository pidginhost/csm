package jstaint

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

func FuzzMayBeJSSource(f *testing.F) {
	for _, src := range []string{
		"const a='\x00';",
		"/*\x00*/const a=1;",
		"const a=`${`\x00`}\x00`;",
		"const a=/[\x00]/;",
		"#!/usr/bin/env node\nconst a='\x00';",
		"\x89PNG\r\n\x1a\n\x00\x00\x00\x0d",
		"PK\x03\x04\x14\x00\x00\x00",
	} {
		f.Add([]byte(src), uint16(len(src)))
	}
	f.Fuzz(func(t *testing.T, src []byte, cut uint16) {
		if len(src) > 64<<10 {
			return
		}
		before := bytes.Clone(src)
		end := int(cut) % (len(src) + 1)
		got := MayBeJSSource(src[:end])
		if !bytes.Equal(src, before) {
			t.Fatal("source gate modified its input")
		}
		if _, err := js.Parse(parse.NewInputBytes(src[:len(src):len(src)]), js.Options{}); err == nil && !got {
			t.Fatalf("valid JavaScript excluded by its prefix: %q", src[:end])
		}
	})
}

func FuzzLiteralText(f *testing.F) {
	f.Add(uint16(js.IdentifierToken), []byte("key"))
	f.Add(uint16(js.StringToken), []byte(`"keydown"`))
	f.Add(uint16(js.StringToken), []byte(`'onkeyup'`))
	f.Add(uint16(js.StringToken), []byte(`"\x6bey"`))
	f.Add(uint16(js.IntegerToken), []byte("1"))
	f.Add(uint16(js.StringToken), []byte{})

	f.Fuzz(func(t *testing.T, rawToken uint16, data []byte) {
		tt := js.TokenType(rawToken)
		got, ok := literalText(tt, data)

		switch tt {
		case js.IdentifierToken:
			if !ok || got != string(data) {
				t.Fatalf("identifier = (%q,%t), want (%q,true)", got, ok, data)
			}
		case js.StringToken:
			valid := len(data) >= 2 && (data[0] == '\'' || data[0] == '"') && data[len(data)-1] == data[0]
			if ok != valid {
				t.Fatalf("string validity = %t, want %t for %q", ok, valid, data)
			}
			if valid && got != string(data[1:len(data)-1]) {
				t.Fatalf("string = %q, want %q", got, data[1:len(data)-1])
			}
		default:
			if ok || got != "" {
				t.Fatalf("non-literal token %d = (%q,%t), want (\"\",false)", tt, got, ok)
			}
		}
	})
}

func FuzzSchemeOfBytes(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("data:text/plain,x"),
		[]byte("JAVASCRIPT:alert(1)"),
		[]byte("https://example.invalid/"),
		[]byte("1data:x"),
		[]byte("relative/path"),
		{},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		got := schemeOfBytes(data)
		if again := schemeOfBytes(data); got != again {
			t.Fatalf("scheme parsing is nondeterministic: first %+v, second %+v", got, again)
		}
		if !got.set {
			return
		}
		if got.name == "" {
			t.Fatal("set scheme has an empty name")
		}
		if !isASCIILetter(got.name[0]) {
			t.Fatalf("scheme name %q does not start with an ASCII letter", got.name)
		}
		if len(data) <= len(got.name) || data[len(got.name)] != ':' {
			t.Fatalf("scheme name %q does not precede a colon in %q", got.name, data)
		}
		for i := range got.name {
			c := got.name[i]
			if !isSchemeChar(c) || (c >= 'A' && c <= 'Z') {
				t.Fatalf("scheme name %q contains invalid normalized byte %q", got.name, c)
			}
			if c != asciiLower(data[i]) {
				t.Fatalf("scheme name %q does not match input prefix %q", got.name, data[:len(got.name)])
			}
		}
	})
}

func FuzzDiscoverHandlers(f *testing.F) {
	seeds := []string{
		`document.onkeydown=(function(e){e.key;});`,
		`document[("onkeypress")]=(e)=>e.which;`,
		`el.addEventListener(("keyup"),function(e){e.code;});`,
		`addEventListener("keydown",function(e){e.keyCode;});`,
		`var h=(e)=>e.charCode;var o={onKeyDown:h};`,
		`el.addEventListener(..."keydown",function(e){e.key;});`,
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, src []byte) {
		if len(src) > MaxSourceBytes {
			return
		}
		ast, err := js.Parse(parse.NewInputBytes(src), js.Options{})
		if err != nil {
			return
		}

		got := handlerIdentities(t, discoverHandlers(ast))
		again := handlerIdentities(t, discoverHandlers(ast))
		if !reflect.DeepEqual(got, again) {
			t.Fatalf("handler discovery is nondeterministic: first %#v, second %#v", got, again)
		}
	})
}

type handlerIdentity struct {
	body     *js.BlockStmt
	eventVar *js.Var
}

func handlerIdentities(t *testing.T, sites []handlerSite) []handlerIdentity {
	t.Helper()
	identities := make([]handlerIdentity, len(sites))
	for i, site := range sites {
		if site.fn == nil || site.fn.body == nil {
			t.Fatalf("handler %d has no function body", i)
		}
		identities[i] = handlerIdentity{body: site.fn.body, eventVar: site.eventVar}
	}
	return identities
}
