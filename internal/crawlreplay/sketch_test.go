package crawlreplay

import (
	"fmt"
	"math/rand/v2"
	"testing"
)

// streamMinutes builds W minutes of random arrivals: a few heavy sources
// that change between minutes plus a tail of light ones.
func streamMinutes(rng *rand.Rand, w int) [][]string {
	out := make([][]string, w)
	for j := range out {
		for h := range 1 + rng.IntN(4) {
			heavy := fmt.Sprintf("heavy-%d-%d", j%3, h)
			for range 5 + rng.IntN(60) {
				out[j] = append(out[j], heavy)
			}
		}
		for range rng.IntN(200) {
			out[j] = append(out[j], fmt.Sprint("light-", rng.IntN(150)))
		}
		rng.Shuffle(len(out[j]), func(a, b int) { out[j][a], out[j][b] = out[j][b], out[j][a] })
	}
	return out
}

func exactOf(minutes [][]string, k int) (int64, int64) {
	w := newWindow()
	for _, arrivals := range minutes {
		m := newMinuteCounts()
		for _, b := range arrivals {
			m.add(&Record{Binding: b})
		}
		w.apply(m, 1)
	}
	return w.Residual(k)
}

func sketchesOf(p SketchParams, minutes [][]string) []*keySketch {
	out := make([]*keySketch, len(minutes))
	for j, arrivals := range minutes {
		out[j] = newKeySketch(p)
		for _, b := range arrivals {
			out[j].add(p, b)
		}
	}
	return out
}

func TestSketchBoundsNeverExceedExact(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	for trial := range 400 {
		w := 1 + rng.IntN(8)
		k := 1 + rng.IntN(10)
		p := SketchParams{M: k + 1 + rng.IntN(40), H: k + 1 + rng.IntN(80), Seed: rng.Uint64()}
		minutes := streamMinutes(rng, w)
		ln, ld := sketchBounds(sketchesOf(p, minutes), k, p.H)
		exactN, exactD := exactOf(minutes, k)
		if ln > exactN || ld > exactD {
			t.Fatalf("trial %d (w=%d k=%d m=%d h=%d): bounds %d,%d exceed exact %d,%d",
				trial, w, k, p.M, p.H, ln, ld, exactN, exactD)
		}
	}
}

func TestSketchBoundsExactWhenSummariesHoldEverything(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))
	minutes := streamMinutes(rng, 5)
	p := SketchParams{M: 10000, H: 10000, Seed: 9}
	ln, ld := sketchBounds(sketchesOf(p, minutes), 4, p.H)
	exactN, exactD := exactOf(minutes, 4)
	if ln != exactN || ld != exactD {
		t.Fatalf("unsaturated bounds %d,%d, want exact %d,%d", ln, ld, exactN, exactD)
	}
}

func TestSketchCollisionsOnlyLowerCardinality(t *testing.T) {
	rng := rand.New(rand.NewPCG(10, 11))
	minutes := streamMinutes(rng, 4)
	p := SketchParams{M: 64, H: 500, Seed: 9}
	wantN, wantD := sketchBounds(sketchesOf(p, minutes), 3, p.H)
	if wantN <= 0 || wantD <= 0 {
		t.Fatalf("fixture needs positive residual bounds, got %d,%d", wantN, wantD)
	}
	collide := p
	collide.Hash = func(string) uint64 { return 42 }
	ln, ld := sketchBounds(sketchesOf(collide, minutes), 3, collide.H)
	if ln != wantN {
		t.Fatalf("hash collisions changed L_N to %d, want %d", ln, wantN)
	}
	if ld != 0 {
		t.Fatalf("all-colliding hashes gave L_D %d, want 0", ld)
	}
}

func TestSpaceSavingInvariants(t *testing.T) {
	rng := rand.New(rand.NewPCG(12, 13))
	for trial := range 200 {
		m := 1 + rng.IntN(20)
		s := newSpaceSaving(m)
		truth := map[string]int64{}
		requests := rng.IntN(500)
		for range requests {
			b := fmt.Sprint("b", rng.IntN(60))
			s.add(b)
			truth[b]++
		}
		wantSize := min(m, len(truth))
		if len(s.entries) != wantSize || len(s.index) != wantSize {
			t.Fatalf("trial %d: entries=%d index=%d, want %d", trial, len(s.entries), len(s.index), wantSize)
		}
		floor := s.floor()
		kept := map[string]bool{}
		var total int64
		for i, e := range s.entries {
			if kept[e.binding] {
				t.Fatalf("trial %d: duplicate counter for %s", trial, e.binding)
			}
			kept[e.binding] = true
			if pos, ok := s.index[e.binding]; !ok || pos != i {
				t.Fatalf("trial %d: counter %d (%s) has index %d, present=%t", trial, i, e.binding, pos, ok)
			}
			total += e.count
			if tr := truth[e.binding]; tr > e.count || tr < e.count-e.err || e.count < floor {
				t.Fatalf("trial %d: entry %+v true %d floor %d", trial, e, tr, floor)
			}
		}
		if total != int64(requests) {
			t.Fatalf("trial %d: counter total %d, want %d requests", trial, total, requests)
		}
		for b, tr := range truth {
			if !kept[b] && tr > floor {
				t.Fatalf("trial %d: absent %s true %d above floor %d", trial, b, tr, floor)
			}
		}
	}
}

func TestBottomHKeepsSmallestDistinct(t *testing.T) {
	b := &bottomH{h: 3}
	for _, x := range []uint64{9, 4, 4, 7, 1, 8, 1} {
		b.add(x)
	}
	if fmt.Sprint(b.hashes) != "[1 4 7]" {
		t.Fatalf("hashes = %v, want [1 4 7]", b.hashes)
	}
}
