package jstaint

import (
	"bytes"
	"testing"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// The deep walk hands every readable file to the JS consumer, and the
// oversize branch recorded a coverage gap for all of them without any
// content check at all -- 118,688 claimed skips over eight weeks on a
// live host, whose examples were .jpg, .png, .zip and .mmdb. Binary
// bytes outside JS literals or comments rule these files out
// without guessing at extensions.
func TestMayBeJSSourceRejectsBinaryContent(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  []byte
		want bool
	}{
		{
			name: "png",
			src:  []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d},
			want: false,
		},
		{
			name: "jpeg",
			src:  []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00},
			want: false,
		},
		{
			name: "zip archive",
			src:  []byte{'P', 'K', 0x03, 0x04, 0x14, 0x00, 0x00, 0x00},
			want: false,
		},
		{
			name: "maxmind database",
			src:  append([]byte("\xab\xcd\xefMaxMind.com"), 0x00, 0x01, 0x02),
			want: false,
		},
		{
			name: "minified script",
			src:  []byte(`!function(e){document.addEventListener("keydown",function(t){fetch("/x",{body:t.key})})}(window);`),
			want: true,
		},
		{
			name: "large plain script",
			src:  bytes.Repeat([]byte("var a = 1;\n"), 512),
			want: true,
		},
		{
			name: "utf8 text with accents",
			src:  []byte("// cofrajă şi descărcare\nconst x = 1;\n"),
			want: true,
		},
		{
			name: "NUL outside a source token",
			src:  []byte("var a=1;\x00\x00binary"),
			want: false,
		},
		{
			name: "syntax error is not proof of binary content",
			src:  []byte("var a=123abc;var b='\x00';"),
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MayBeJSSource(tc.src); got != tc.want {
				t.Errorf("MayBeJSSource() = %v, want %v", got, tc.want)
			}
		})
	}
}

// NUL is legal inside literals and comments. Check every cut of each valid
// program because an oversize peek can end in the middle of any token.
func TestMayBeJSSourceAdmitsNULInSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{"single quoted string", "const a='\x00';"},
		{"double quoted string", "const a=\"\x00\";"},
		{"escaped quote", `const a='\'` + "\x00';"},
		{"template", "const a=`\x00${1}tail\x00`;"},
		{"nested template", "const a=`${`\x00`}\x00`;"},
		{"block comment", "/*! retained license \x00 */const a=1;"},
		{"line comment", "// \x00\nconst a=1;"},
		{"html comment", "<!-- \x00\nconst a=1;"},
		{"hashbang", "#!/usr/bin/env node\nconst a='\x00';"},
		{"regexp", "const a=/[\x00]/;"},
		{"regexp after division", "const a=1 / /[\x00]/.source.length;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := []byte(tc.src)
			if _, err := js.Parse(parse.NewInputBytes(src[:len(src):len(src)]), js.Options{}); err != nil {
				t.Fatalf("fixture is not valid JavaScript: %v", err)
			}
			for end := 0; end <= len(src); end++ {
				if !MayBeJSSource(src[:end]) {
					t.Errorf("valid source prefix ending at %d was excluded: %q", end, src[:end])
				}
			}
			if string(src) != tc.src {
				t.Fatal("source gate modified its input")
			}
		})
	}
}
