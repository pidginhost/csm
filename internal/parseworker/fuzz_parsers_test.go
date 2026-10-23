package parseworker

import (
	"bytes"
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/zipdir"
)

func FuzzReadEntries(f *testing.F) {
	f.Add([]byte{}, uint64(0))
	f.Add([]byte{0, 0, 1, 'a', 1, 0, 2, 'b', '/'}, uint64(2*zipdir.HeaderLen+3))
	f.Add([]byte{2, 0, 0}, uint64(zipdir.HeaderLen))
	f.Add(make([]byte, 30), uint64(2*zipdir.HeaderLen))
	f.Fuzz(func(t *testing.T, data []byte, budget uint64) {
		var again bytes.Buffer
		var visited, spent uint64
		n, err := readEntries(context.Background(), bytes.NewReader(data), budget, func(name string, dir bool) error {
			visited++
			spent += uint64(zipdir.HeaderLen + len(name))
			return writeEntry(&again, name, dir)
		})
		if n != visited || spent > budget {
			t.Fatalf("count=%d visits=%d spent=%d budget=%d", n, visited, spent, budget)
		}
		if err == nil && !bytes.Equal(again.Bytes(), data) {
			t.Fatalf("re-encoding %x gave %x", data, again.Bytes())
		}
	})
}
