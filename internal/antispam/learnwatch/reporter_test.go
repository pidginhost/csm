package learnwatch

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/store"
)

func TestReporterIDDeterministicAndRange(t *testing.T) {
	seen := map[int]string{}
	for i := range 5000 {
		domain := fmt.Sprintf("d%d.example.com", i)
		id := ReporterID(antispam.ReporterDomain, domain, "")
		if again := ReporterID(antispam.ReporterDomain, domain, "x@"+domain); again != id {
			t.Fatalf("%s: %d then %d", domain, id, again)
		}
		if id < 1<<32 || id >= 1<<62 || id == -1 {
			t.Fatalf("%s: id %d out of range", domain, id)
		}
		if other, dup := seen[id]; dup {
			t.Fatalf("%s and %s share id %d", domain, other, id)
		}
		seen[id] = domain
	}
	box := ReporterID(antispam.ReporterMailbox, "example.com", "a@example.com")
	if box == ReporterID(antispam.ReporterMailbox, "example.com", "b@example.com") ||
		box == ReporterID(antispam.ReporterDomain, "example.com", "a@example.com") || box < 1<<32 {
		t.Fatalf("mailbox ids do not split: %d", box)
	}
	// Pinned: the id must survive restarts, releases and ResetLearnWatch.
	// The second hash has bit 32 clear and a top bit set.
	for _, c := range []struct {
		mode, domain, mailbox string
		want                  int
	}{
		{antispam.ReporterDomain, "example.com", "", 0x0a75b1b35db8ea04},
		{antispam.ReporterMailbox, "example.com", "alice@example.com", 0x3cf558bbbd139f6f},
	} {
		if got := ReporterID(c.mode, c.domain, c.mailbox); got != c.want {
			t.Errorf("%s %s%s is %#x, want %#x", c.mode, c.domain, c.mailbox, got, c.want)
		}
	}
}

// Existing watcher state is keyed by an 8-byte big-endian UID; reporter
// ids keep that layout and sort before the meta and pending keys.
func TestUIDPrefixKeepsAccountKeys(t *testing.T) {
	k := FolderKey{UID: 1001, Domain: "example.com", Box: "info", Folder: ".spam"}
	if want := []byte("\x00\x00\x00\x00\x00\x00\x03\xe9\x00example.com\x00info\x00.spam"); !bytes.Equal(k.key(), want) {
		t.Fatalf("key %q", k.key())
	}
	id := ReporterID(antispam.ReporterDomain, "example.com", "")
	if p := uidPrefix(id); len(p) != 8 || p[0] >= cursorKey[0] {
		t.Fatalf("reporter prefix %x", p)
	}
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := NewState(db, func() time.Time { return t0 })
	var got int
	err = s.Update(func(tx StateTx) error { return tx.SetCursor(id) })
	if err == nil {
		err = s.View(func(tx StateTx) (e error) { got, e = tx.Cursor(); return e })
	}
	if err != nil || got != id {
		t.Fatalf("cursor %d, want %d, err %v", got, id, err)
	}
}
