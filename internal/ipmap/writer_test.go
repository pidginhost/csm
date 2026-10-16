package ipmap

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func testWriter(t *testing.T) *Writer {
	w := NewWriter(filepath.Join(t.TempDir(), "csm_ip.map"))
	w.chown = func(string, int) error { return nil }
	return w
}

func TestWriterWritesOnlyChanges(t *testing.T) {
	w := testWriter(t)
	m := Build(Sources{Entries: map[string][]string{Spam.Name: {"203.0.113.40"}}})
	if wrote, err := w.Write(m, 974, now); !wrote || err != nil {
		t.Fatalf("first write = %v, %v", wrote, err)
	}
	info, err := os.Stat(w.Path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("map file %v, %v", info, err)
	}
	if wrote, err := w.Write(m, 974, now.Add(time.Minute)); wrote || err != nil {
		t.Fatalf("unchanged map rewritten: %v, %v", wrote, err)
	}
	st := w.State()
	if st.Gen == "" || !st.WrittenAt.Equal(now) || st.Err != nil {
		t.Fatalf("state %+v", st)
	}
	if w.Weight(addr("203.0.113.40")) != Spam.Tenths() {
		t.Fatal("lookup does not follow the written map")
	}
}

func TestWriterKeepsTheOldFileOnFailure(t *testing.T) {
	w := testWriter(t)
	old := Build(Sources{Entries: map[string][]string{Spam.Name: {"203.0.113.41"}}})
	if _, err := w.Write(old, 974, now); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(w.Path)
	w.chown = func(string, int) error { return errors.New("operation not permitted") }
	if wrote, err := w.Write(Build(Sources{Entries: map[string][]string{Spam.Name: {"203.0.113.42"}}}), 974, now.Add(time.Minute)); wrote || err == nil {
		t.Fatalf("failed write = %v, %v", wrote, err)
	}
	after, _ := os.ReadFile(w.Path)
	if string(after) != string(before) || w.Weight(addr("203.0.113.41")) != Spam.Tenths() || w.State().Err == nil {
		t.Fatal("a failed write changed the file, the lookup or hid the error")
	}
	if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(w.Path), ".csm_ip.map.*")); len(matches) != 0 {
		t.Fatalf("temporary files left: %v", matches)
	}
}

func TestWriterNeedsRspamdGroup(t *testing.T) {
	w := testWriter(t)
	if wrote, err := w.Write(Build(Sources{}), -1, now); wrote || err == nil {
		t.Fatal("wrote a map rspamd cannot read")
	}
}

func TestWriterRemove(t *testing.T) {
	w := testWriter(t)
	if _, err := w.Write(Build(Sources{Entries: map[string][]string{CINS.Name: {"203.0.113.43"}}}), 974, now); err != nil {
		t.Fatal(err)
	}
	if err := w.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(w.Path); !os.IsNotExist(err) || w.State().Gen != "" || w.Weight(addr("203.0.113.43")) != 0 {
		t.Fatal("remove left the file or the state")
	}
	if err := w.Remove(); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}
