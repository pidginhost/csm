package mysqlclient

import "testing"

// TestBatchUnescape_RoundTripsBatchEscape proves BatchUnescape is the exact
// inverse of mysqlBatchEscape: any value survives escape-then-unescape
// byte-for-byte. This is the property the wp_options auto-clean relies on so
// the option and its backup copy are stored as the true original bytes rather
// than the batch-mode escaped text.
func TestBatchUnescape_RoundTripsBatchEscape(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"plain", "hello world"},
		{"newline", "line1\nline2"},
		{"tab", "col1\tcol2"},
		{"cr", "a\rb"},
		{"nul", "a\x00b"},
		{"backslash", `C:\path\to\file`},
		{"literal_backslash_n", `not a newline: \n stays`},
		{"mixed_control", "a\tb\nc\\d\x00e\rf"},
		{
			// PHP-serialized string whose length prefix counts the raw
			// newline byte. If the newline round-trips as a literal "\n"
			// (two bytes) the s:11 prefix no longer matches the payload and
			// unserialize() breaks.
			"php_serialized_newline",
			"a:1:{s:3:\"css\";s:11:\"line1\nline2\";}",
		},
		{
			"php_serialized_backslash",
			`a:1:{s:4:"path";s:11:"C:\dir\file";}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			escaped := mysqlBatchEscape(tc.in)
			got := BatchUnescape(escaped)
			if got != tc.in {
				t.Fatalf("round-trip mismatch\n in:      %q\n escaped: %q\n got:     %q", tc.in, escaped, got)
			}
		})
	}
}

// TestBatchUnescape_NewlineNotLeftLiteral is the direct regression for the
// corruption bug: the batch output for a real newline is the two-byte sequence
// backslash-n, and BatchUnescape must turn it back into one 0x0A byte.
func TestBatchUnescape_NewlineNotLeftLiteral(t *testing.T) {
	escaped := mysqlBatchEscape("line1\nline2")
	if escaped != `line1\nline2` {
		t.Fatalf("precondition: batch escape of newline = %q, want literal backslash-n", escaped)
	}
	got := BatchUnescape(escaped)
	if got != "line1\nline2" {
		t.Fatalf("BatchUnescape kept literal escape: got %q", got)
	}
	if len(got) != 11 {
		t.Fatalf("decoded length = %d, want 11 (real newline is one byte)", len(got))
	}
}
