package phptaint

import (
	"bytes"
	"testing"
)

// The open-tag list includes the bare two-byte "<?" so short_open_tag
// sources are admitted. That needle is short enough to appear by chance
// in binary content: over a 64KB peek roughly two thirds of media files
// carry it somewhere. Every one of them was then reported as PHP the
// scan failed to examine. PHP source is text where it opens, so the tag
// has to appear before the first NUL byte: binary headers carry a NUL
// early and the chance sequence later. Real short-tag sources survive,
// and so does a dropper that opens with a tag and embeds a binary
// payload further down.
func TestMayBePHPSourceRejectsBinaryContent(t *testing.T) {
	pngPrefix := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R'}

	for _, tc := range []struct {
		name string
		src  []byte
		want bool
	}{
		{
			name: "png carrying a chance open tag",
			src:  append(append([]byte{}, pngPrefix...), []byte("\x00\x01<?\x02\x03rest of the pixels")...),
			want: false,
		},
		{
			name: "png carrying a chance full tag",
			src:  append(append([]byte{}, pngPrefix...), []byte("\x00<?php\x00junk")...),
			want: false,
		},
		{
			name: "gettext catalog with a chance open tag",
			src:  append([]byte{0xde, 0x12, 0x04, 0x95, 0x00, 0x00, 0x00, 0x00}, []byte("msgid<?msgstr")...),
			want: false,
		},
		{
			name: "zip archive with a chance open tag",
			src:  append([]byte{'P', 'K', 0x03, 0x04, 0x14, 0x00, 0x00, 0x00}, []byte("<?data")...),
			want: false,
		},
		{
			name: "short tag source stays admitted",
			src:  []byte("<? echo 'ok'; ?>"),
			want: true,
		},
		{
			name: "full tag source stays admitted",
			src:  []byte("#!/usr/bin/php\n<?php echo 'ok';"),
			want: true,
		},
		{
			name: "full tag before embedded binary payload",
			src:  []byte("<?php __halt_compiler();\x00\xffpayload"),
			want: true,
		},
		{
			name: "short tag before embedded binary payload",
			src:  []byte("<? echo 'ok'; ?>\x00\xffpayload"),
			want: true,
		},
		{
			name: "echo tag before embedded binary payload",
			src:  []byte("<?= 'ok' ?>\x00\xffpayload"),
			want: true,
		},
		{
			name: "large text source with a trailing tag stays admitted",
			src:  append(bytes.Repeat([]byte("plain text line\n"), 64), []byte("<?= $value ?>")...),
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MayBePHPSource(tc.src); got != tc.want {
				t.Errorf("MayBePHPSource() = %v, want %v", got, tc.want)
			}
		})
	}
}
