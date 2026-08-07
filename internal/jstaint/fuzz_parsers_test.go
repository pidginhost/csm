package jstaint

import (
	"testing"

	"github.com/tdewolff/parse/v2/js"
)

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
