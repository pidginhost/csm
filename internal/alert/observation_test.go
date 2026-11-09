package alert

import (
	"strings"
	"testing"
)

func printableToken(t *testing.T, kind, token string) {
	t.Helper()
	if token == "" || len(token) > 128 {
		t.Fatalf("%s %q is not a bounded token", kind, token)
	}
	for i := range token {
		if token[i] < 0x21 || token[i] > 0x7e {
			t.Fatalf("%s %q contains a non-token byte", kind, token)
		}
	}
}

// A file's stream names the file by device and inode only, so every reader
// of one file names it alike, before and after a restart.
func TestFileStreamNamesTheFile(t *testing.T) {
	a := FileStream(0x803, 0x1a2b)
	if a != "f:803:1a2b" {
		t.Fatalf("stream %q, want f:803:1a2b", a)
	}
	printableToken(t, "stream", FileStream(^uint64(0), ^uint64(0)))
	if FileStream(0x803, 0x1a2c) == a || FileStream(0x804, 0x1a2b) == a {
		t.Fatal("another file shares the stream")
	}
}

// A record's cursor names its offset and its bytes: a record rewritten at an
// offset gets another cursor, and the same bytes read again keep theirs,
// whichever line ending the reader left on them.
func TestRecordCursorNamesPositionAndBytes(t *testing.T) {
	a := RecordCursor(128, "Nov  9 12:00:01 host sshd[1]: Accepted")
	if !strings.HasPrefix(a, "128:") || len(a) != len("128:")+16 {
		t.Fatalf("cursor %q, want the offset and 16 hex digits", a)
	}
	printableToken(t, "cursor", RecordCursor(1<<62, strings.Repeat("x", 4096)))
	for _, same := range []string{
		"Nov  9 12:00:01 host sshd[1]: Accepted\n",
		"Nov  9 12:00:01 host sshd[1]: Accepted\r\n",
		"Nov  9 12:00:01 host sshd[1]: Accepted\r",
	} {
		if got := RecordCursor(128, same); got != a {
			t.Errorf("cursor of %q is %q, want %q", same, got, a)
		}
	}
	for name, other := range map[string]string{
		"other offset": RecordCursor(129, "Nov  9 12:00:01 host sshd[1]: Accepted"),
		"other bytes":  RecordCursor(128, "Nov  9 12:00:02 host sshd[1]: Accepted"),
		"empty":        RecordCursor(128, ""),
	} {
		if other == a {
			t.Errorf("%s shares cursor %q", name, a)
		}
	}
}
