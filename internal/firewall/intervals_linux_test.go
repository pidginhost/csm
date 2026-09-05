//go:build linux

package firewall

import (
	"bytes"
	"math/rand/v2"
	"reflect"
	"testing"

	"github.com/google/nftables"
)

func TestNormalizedIntervalsPreserveCoverageAndInputs(t *testing.T) {
	rng := rand.New(rand.NewPCG(17, 29))
	for _, width := range []int{4, 16} {
		key := func(last int) []byte {
			out := make([]byte, width)
			out[width-2] = byte(last / 256)
			out[width-1] = byte(last % 256)
			return out
		}
		for range 100 {
			var input []nftables.SetElement
			var covered [257]bool
			for range 16 {
				first, last := rng.IntN(256), rng.IntN(256)
				if first > last {
					first, last = last, first
				}
				input = appendIntervalSetElements(input, key(first), key(last))
				for i := first; i <= last; i++ {
					covered[i] = true
				}
			}
			original := make([]nftables.SetElement, len(input))
			for i, element := range input {
				original[i] = element
				original[i].Key = bytes.Clone(element.Key)
			}
			got := normalizeIntervalElements(input)
			if !reflect.DeepEqual(input, original) {
				t.Fatal("normalizing changed source entries")
			}
			for i := 1; i < len(got); i++ {
				if bytes.Compare(got[i-1].Key, got[i].Key) >= 0 || got[i-1].IntervalEnd == got[i].IntervalEnd {
					t.Fatalf("overlapping or redundant boundaries: %+v", got)
				}
			}
			for address, want := range covered {
				inside := false
				for _, boundary := range got {
					if bytes.Compare(boundary.Key, key(address)) > 0 {
						break
					}
					inside = !boundary.IntervalEnd
				}
				if inside != want {
					t.Fatalf("width %d address %d covered=%v, want %v", width, address, inside, want)
				}
			}
		}
	}
}
