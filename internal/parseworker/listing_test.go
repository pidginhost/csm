package parseworker

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/zipdir"
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
	n, err := readEntries(context.Background(), &buf, 1<<20, func(name string, dir bool) error {
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
		if _, err := readEntries(context.Background(), bytes.NewReader(data), 1<<20, func(string, bool) error { return nil }); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	stop := errors.New("stop")
	if _, err := readEntries(context.Background(), bytes.NewReader([]byte{0, 0, 1, 'a'}), 1<<20, func(string, bool) error { return stop }); err != stop {
		t.Fatalf("visit error = %v, want it unwrapped", err)
	}
}

func TestReadEntriesEnforcesDirectoryBudget(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    []byte
		budget  uint64
		visited uint64
		limited bool
	}{
		{"empty", nil, 0, 0, false},
		{"exact", []byte{0, 0, 1, 'a'}, zipdir.HeaderLen + 1, 1, false},
		{"name over budget", []byte{0, 0, 1, 'a'}, zipdir.HeaderLen, 0, true},
		{"name length before payload", []byte{0, 255, 255}, zipdir.HeaderLen, 0, true},
		{"record over budget", []byte{0, 0, 0}, 0, 0, true},
		{"empty name flood", make([]byte, 30), 2 * zipdir.HeaderLen, 2, true},
		{"aggregate names", []byte{0, 0, 1, 'a', 0, 0, 1, 'b'}, 2*zipdir.HeaderLen + 1, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var visited uint64
			n, err := readEntries(context.Background(), bytes.NewReader(tc.data), tc.budget, func(string, bool) error {
				visited++
				return nil
			})
			if n != tc.visited || visited != tc.visited || (tc.limited && !errors.Is(err, zipdir.ErrScanLimit)) || (!tc.limited && err != nil) {
				t.Fatalf("readEntries = %d, %v, visits = %d; want %d, limited=%t", n, err, visited, tc.visited, tc.limited)
			}
		})
	}
}

func TestReadEntriesStopsOnCancellation(t *testing.T) {
	for _, before := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if before {
			cancel()
		}
		var visits uint64
		n, err := readEntries(ctx, bytes.NewReader(make([]byte, 30)), 1<<20, func(string, bool) error {
			visits++
			cancel()
			return nil
		})
		cancel()
		want := uint64(1)
		if before {
			want = 0
		}
		if !errors.Is(err, context.Canceled) || n != want || visits != want {
			t.Fatalf("canceled before=%t: readEntries = %d, %v, visits = %d; want %d", before, n, err, visits, want)
		}
	}
}

// A compromised worker can return a sparse listing full of empty names.
// The daemon must bound work by the request, not by a worker-supplied size.
func TestReadEntriesBoundsEndlessListing(t *testing.T) {
	var visits uint64
	n, err := readEntries(context.Background(), zeroListing{}, 2*zipdir.HeaderLen, func(string, bool) error {
		visits++
		if visits > 10 {
			return io.ErrNoProgress
		}
		return nil
	})
	if !errors.Is(err, zipdir.ErrScanLimit) || n != 2 || visits != 2 {
		t.Fatalf("endless listing = %d, %v, visits = %d", n, err, visits)
	}
}

type zeroListing struct{}

func (zeroListing) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
