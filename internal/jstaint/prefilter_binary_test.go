package jstaint

import (
	"bytes"
	"testing"
)

// The deep walk hands every readable file to the JS consumer, and the
// oversize branch recorded a coverage gap for all of them without any
// content check at all -- 118,688 claimed skips over eight weeks on a
// live host, whose examples were .jpg, .png, .zip and .mmdb. JavaScript
// source is text, so a NUL byte in the peeked prefix rules a file out
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MayBeJSSource(tc.src); got != tc.want {
				t.Errorf("MayBeJSSource() = %v, want %v", got, tc.want)
			}
		})
	}
}
