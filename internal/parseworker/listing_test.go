package parseworker

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

type entry struct {
	name string
	dir  bool
}

func zipBytes(t testing.TB, names ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range names {
		if _, err := zw.Create(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestListEntriesVisitsEveryEntryInOrder(t *testing.T) {
	data := zipBytes(t, "a/", "a/b.php", "c.txt")
	var got []entry
	err := ListEntries(context.Background(), bytes.NewReader(data), int64(len(data)), 1<<20, func(name string, dir bool) error {
		got = append(got, entry{name, dir})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []entry{{"a/", true}, {"a/b.php", false}, {"c.txt", false}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestEntryCodecRoundTrip(t *testing.T) {
	want := []entry{{"", false}, {strings.Repeat("n", 65535), true}, {"line\nbreak", false}}
	var buf bytes.Buffer
	for _, e := range want {
		if err := writeEntry(&buf, e.name, e.dir); err != nil {
			t.Fatal(err)
		}
	}
	var got []entry
	n, err := readEntries(&buf, func(name string, dir bool) error {
		got = append(got, entry{name, dir})
		return nil
	})
	if err != nil || n != uint64(len(want)) {
		t.Fatalf("readEntries = %d, %v", n, err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d differs", i)
		}
	}
	if err := writeEntry(&buf, strings.Repeat("n", 65536), false); err == nil {
		t.Fatal("65536-byte name encoded")
	}
}

func TestReadEntriesRejectsBadRecords(t *testing.T) {
	for name, data := range map[string][]byte{
		"short name": {0, 0, 10, 'a', 'b', 'c'},
		"short head": {0, 0},
		"bad flag":   {2, 0, 1, 'a'},
	} {
		if _, err := readEntries(bytes.NewReader(data), func(string, bool) error { return nil }); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	stop := errors.New("stop")
	if _, err := readEntries(bytes.NewReader([]byte{0, 0, 1, 'a'}), func(string, bool) error { return stop }); err != stop {
		t.Fatalf("visit error = %v, want it unwrapped", err)
	}
}

func FuzzReadEntries(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 1, 'a', 1, 0, 2, 'b', '/'})
	f.Add([]byte{2, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		var again bytes.Buffer
		_, err := readEntries(bytes.NewReader(data), func(name string, dir bool) error {
			return writeEntry(&again, name, dir)
		})
		if err == nil && !bytes.Equal(again.Bytes(), data) {
			t.Fatalf("re-encoding %x gave %x", data, again.Bytes())
		}
	})
}
