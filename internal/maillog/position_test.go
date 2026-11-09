package maillog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A file line's stream names the file by device and inode, the same before
// and after a restart; its cursor names the line's offset and bytes.
func TestFileReaderPositionNamesFileOffsetAndBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maillog")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	dev, ino := fileIdentity(info)
	a := filePosition(dev, ino, 0, "first\n")
	if a.Stream != alert.FileStream(dev, ino) || a.Cursor != alert.RecordCursor(0, "first") || a.ObservedAt.IsZero() {
		t.Fatalf("position %+v, want the file and the line's offset and bytes", a)
	}
	if b := filePosition(dev, ino, 0, "other\n"); b.Stream != a.Stream || b.Cursor == a.Cursor {
		t.Fatalf("another line at the offset named %+v like %+v", b, a)
	}
}

// A journald cursor grows past admission's 128-byte bound on a busy host.
// The encoded cursor is bounded, a printable token, the same for the same
// cursor and different for another one.
func TestJournalCursorIsBoundedAndStable(t *testing.T) {
	raw := "s=" + strings.Repeat("a", 32) + ";i=" + strings.Repeat("f", 16) + ";b=" + strings.Repeat("b", 32) +
		";m=" + strings.Repeat("e", 16) + ";t=" + strings.Repeat("c", 16) + ";x=" + strings.Repeat("d", 16)
	if len(raw) <= 128 {
		t.Fatalf("fixture cursor is %d bytes, want one over the bound", len(raw))
	}
	got := journalCursor(raw)
	if len(got) > 128 || !strings.HasPrefix(got, "jc1:") || got != journalCursor(raw) || got == journalCursor(raw+"0") {
		t.Fatalf("encoded cursor %q is not bounded, versioned, stable and distinct", got)
	}
	for i := 0; i < len(got); i++ {
		if got[i] < 0x21 || got[i] > 0x7e {
			t.Fatalf("encoded cursor %q has a byte admission refuses", got)
		}
	}
	if journalCursor("") != "" {
		t.Fatal("an entry without a cursor got a position")
	}
}
