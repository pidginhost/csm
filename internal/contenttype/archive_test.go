package contenttype

import "testing"

func TestIsCompressedArchive(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "zip local header", data: []byte{'P', 'K', 0x03, 0x04}, want: true},
		{name: "zip empty archive", data: []byte{'P', 'K', 0x05, 0x06}, want: true},
		{name: "zip data descriptor", data: []byte{'P', 'K', 0x07, 0x08}, want: true},
		{name: "gzip", data: []byte{0x1f, 0x8b, 0x08, 0x00}, want: true},
		{name: "bzip2", data: []byte{'B', 'Z', 'h', '9'}, want: true},
		{name: "xz", data: []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, want: true},
		{name: "7z", data: []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, want: true},
		{name: "rar4", data: []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x00}, want: true},
		{name: "rar5", data: []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}, want: true},
		{name: "empty", data: nil},
		{name: "three byte bzip2 prefix", data: []byte{'B', 'Z', 'h'}},
		{name: "three byte gzip prefix", data: []byte{0x1f, 0x8b, 0x08}},
		{name: "truncated zip", data: []byte{'P', 'K', 0x03}},
		{name: "invalid zip fourth byte", data: []byte{'P', 'K', 0x03, 'X'}},
		{name: "invalid empty zip fourth byte", data: []byte{'P', 'K', 0x05, 'X'}},
		{name: "invalid descriptor fourth byte", data: []byte{'P', 'K', 0x07, 'X'}},
		{name: "invalid xz suffix", data: []byte{0xfd, '7', 'z', 'X', 'X', 0x00}},
		{name: "invalid 7z suffix", data: []byte{'7', 'z', 0xbc, 0xaf, 0x00, 0x00}},
		{name: "invalid rar suffix", data: []byte("Rar! ordinary text")},
		{name: "php", data: []byte("<?php system($_POST['cmd']);")},
		{name: "html", data: []byte("<!doctype html><form>login</form>")},
		{name: "phar", data: []byte("<?php __HALT_COMPILER();")},
		{name: "tar", data: append(make([]byte, 257), []byte("ustar")...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCompressedArchive(tt.data); got != tt.want {
				t.Errorf("IsCompressedArchive() = %t, want %t", got, tt.want)
			}
		})
	}
}
