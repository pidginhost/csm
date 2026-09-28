package crawlreplay

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"reflect"
	"slices"
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
		bounds := composeSketches(sketchesOf(p, minutes), k, p.H)
		ln, ld := bounds.LN, bounds.LD
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
	bounds := composeSketches(sketchesOf(p, minutes), 4, p.H)
	ln, ld := bounds.LN, bounds.LD
	exactN, exactD := exactOf(minutes, 4)
	if ln != exactN || ld != exactD {
		t.Fatalf("unsaturated bounds %d,%d, want exact %d,%d", ln, ld, exactN, exactD)
	}
}

func TestSketchCollisionsOnlyLowerCardinality(t *testing.T) {
	rng := rand.New(rand.NewPCG(10, 11))
	minutes := streamMinutes(rng, 4)
	p := SketchParams{M: 64, H: 500, Seed: 9}
	want := composeSketches(sketchesOf(p, minutes), 3, p.H)
	wantN, wantD := want.LN, want.LD
	if wantN <= 0 || wantD <= 0 {
		t.Fatalf("fixture needs positive residual bounds, got %d,%d", wantN, wantD)
	}
	collide := p
	collide.Hash = func(string) uint64 { return 42 }
	got := composeSketches(sketchesOf(collide, minutes), 3, collide.H)
	ln, ld := got.LN, got.LD
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

// letterHash gives every one-letter binding its own ordered hash, so a
// test names exactly which bindings a bottom-h set keeps.
func letterHash(b string) uint64 { return uint64(b[0]) }

func sketchOfArrivals(p SketchParams, arrivals string) *keySketch {
	ks := newKeySketch(p)
	for _, b := range arrivals {
		ks.add(p, string(b))
	}
	return ks
}

func exactOfArrivals(minutes []string, k int) (int64, int64) {
	split := make([][]string, len(minutes))
	for j, arrivals := range minutes {
		for _, b := range arrivals {
			split[j] = append(split[j], string(b))
		}
	}
	return exactOf(split, k)
}

// checkComposition asserts the bounds spec 6.3 promises for any window.
func checkComposition(t *testing.T, got sketchWindow, exactN, exactD int64, k, m int) {
	t.Helper()
	switch {
	case got.LN < 0, got.LD < 0, got.LN > exactN, got.LD > exactD:
		t.Fatalf("bounds %d,%d outside [0, exact %d,%d]", got.LN, got.LD, exactN, exactD)
	case got.B*int64(m) > got.N:
		t.Fatalf("B=%d exceeds N/m with N=%d m=%d", got.B, got.N, m)
	case exactN-got.LN > int64(k)*got.B:
		t.Fatalf("residual shortfall %d exceeds K*B=%d", exactN-got.LN, int64(k)*got.B)
	}
}

func TestSketchCompositionBoundaries(t *testing.T) {
	compose := func(p SketchParams, k int, minutes ...string) sketchWindow {
		sketches := make([]*keySketch, len(minutes))
		for j, arrivals := range minutes {
			sketches[j] = sketchOfArrivals(p, arrivals)
		}
		return composeSketches(sketches, k, p.H)
	}

	t.Run("spec example", func(t *testing.T) {
		p := SketchParams{M: 2, H: 4, Hash: letterHash}
		minutes := []string{"aaaaabc", "dddddbe"}
		got := compose(p, 1, minutes...)
		want := map[string]int64{"a": 7, "c": 4, "d": 7, "e": 4}
		if got.N != 14 || got.B != 4 || !maps.Equal(got.Upper, want) || got.Top != 7 || got.LN != 7 {
			t.Fatalf("N=%d B=%d U=%v top=%d L_N=%d, want 14, 4, %v, 7, 7", got.N, got.B, got.Upper, got.Top, got.LN, want)
		}
		// The window union keeps a..d; summing each minute's three would claim five.
		if got.S != 4 || got.LD != 3 {
			t.Fatalf("s=%d L_D=%d, want 4 and 3", got.S, got.LD)
		}
		exactN, exactD := exactOfArrivals(minutes, 1)
		if exactN != 9 || exactD != 4 {
			t.Fatalf("exact residual %d,%d, want 9,4", exactN, exactD)
		}
		checkComposition(t, got, exactN, exactD, 1, p.M)
	})

	t.Run("empty summaries", func(t *testing.T) {
		p := SketchParams{M: 3, H: 8, Hash: letterHash}
		got := compose(p, 2, "", "", "")
		if got.N != 0 || got.B != 0 || got.Top != 0 || got.LN != 0 || got.S != 0 || got.LD != 0 || len(got.Upper) != 0 {
			t.Fatalf("empty window %+v", got)
		}
		checkComposition(t, got, 0, 0, 2, p.M)
	})

	t.Run("padding to K with B", func(t *testing.T) {
		// Outside the detector's m > K domain only the padding can supply K
		// values; it must use B, the bound for every unseen binding.
		p := SketchParams{M: 2, H: 8, Hash: letterHash}
		got := compose(p, 3, "aab")
		if got.B != 1 || got.Top != 2+1+1 || got.LN != 0 {
			t.Fatalf("B=%d top=%d L_N=%d, want 1, 4, 0", got.B, got.Top, got.LN)
		}
		exactN, exactD := exactOfArrivals([]string{"aab"}, 3)
		checkComposition(t, got, exactN, exactD, 3, p.M)
		p.M = 3
		unfull := compose(p, 2, "a")
		if unfull.B != 0 || unfull.Top != 1 || unfull.LN != 0 || unfull.LD != 0 {
			t.Fatalf("unfull summary %+v, want B=0 top=1 and zero bounds", unfull)
		}
	})

	t.Run("ties are canonical", func(t *testing.T) {
		p := SketchParams{M: 2, H: 8, Hash: letterHash}
		for _, arrivals := range []string{"abc", "bac"} {
			ks := sketchOfArrivals(p, arrivals)
			kept := map[string]int64{}
			for _, e := range ks.ss.entries {
				kept[e.binding] = e.count
			}
			if !maps.Equal(kept, map[string]int64{"b": 1, "c": 2}) {
				t.Fatalf("%s: kept %v, want the smallest tied binding replaced", arrivals, kept)
			}
		}
		if a, b := compose(p, 1, "abc"), compose(p, 1, "bac"); !reflect.DeepEqual(a, b) {
			t.Fatalf("tie order changed the window: %+v and %+v", a, b)
		}
	})

	t.Run("reordered arrivals stay sound", func(t *testing.T) {
		rng := rand.New(rand.NewPCG(31, 32))
		p := SketchParams{M: 4, H: 6, Seed: 3}
		base := []string{"aaaaaaabbbccddefghij", "kkkkkkkaaabbccclmnop", "qqqqqqqrrrsstuvwxyza"}
		for trial := range 300 {
			minutes := slices.Clone(base)
			for j := range minutes {
				r := []rune(minutes[j])
				rng.Shuffle(len(r), func(a, b int) { r[a], r[b] = r[b], r[a] })
				minutes[j] = string(r)
			}
			k := 1 + trial%3
			exactN, exactD := exactOfArrivals(minutes, k)
			checkComposition(t, compose(p, k, minutes...), exactN, exactD, k, p.M)
		}
	})

	// At m = K+1 and h = D+K, the smallest summaries the domain allows, a
	// replay's bounds at every minute equal a fresh composition of the last
	// W minutes' summaries: whole minutes expire, nothing is subtracted.
	t.Run("rollover at the smallest summaries", func(t *testing.T) {
		p := Params{W: 3, R: 2, F: 1, K: 2, D: 3, C: 80, Baseline: BaselineParams{Alpha: 0.5, MinObs: 1, MinAge: 1 << 40, FloorPerMin: 1}}
		sk := SketchParams{M: p.K + 1, H: p.D + p.K, Seed: 17}
		rng := rand.New(rand.NewPCG(41, 42))
		var recs []Record
		var seq int64
		for m := fixtureStart; m < fixtureStart+12; m++ {
			for range rng.IntN(40) {
				seq++
				recs = append(recs, Record{T: m*60 + 1, Seq: seq, Site: testSite, Binding: synthBinding(uint64(rng.IntN(9))),
					Class: ClassExpensive, L2: SynthKey(1), L1: SynthKey(2), Status: 200})
			}
		}
		site := Site{Records: recs, Coverage: []Span{{From: fixtureStart, To: fixtureStart + 11}}}
		byMinute := map[int64][]string{}
		for _, r := range recs {
			byMinute[r.T/60] = append(byMinute[r.T/60], r.Binding)
		}
		ticks := 0
		if err := ReplaySite(site, p, Options{Sketch: &sk}, func(tk Tick) {
			var minutes [][]string
			for j := tk.Minute - int64(p.W) + 1; j <= tk.Minute; j++ {
				minutes = append(minutes, byMinute[j])
			}
			want := composeSketches(sketchesOf(sk, minutes), p.K, sk.H)
			exactN, exactD := exactOf(minutes, p.K)
			for _, e := range tk.Evaluations {
				if e.Key.Level != 1 {
					continue
				}
				ticks++
				if e.Residual != want.LN || e.Distinct != want.LD || e.ExactResidual != exactN || e.ExactDistinct != exactD {
					t.Fatalf("minute %d: %d,%d exact %d,%d; want %d,%d exact %d,%d", tk.Minute-fixtureStart,
						e.Residual, e.Distinct, e.ExactResidual, e.ExactDistinct, want.LN, want.LD, exactN, exactD)
				}
			}
		}); err != nil {
			t.Fatal(err)
		}
		if ticks != 12-p.W+1 {
			t.Fatalf("%d L1 evaluations, want %d", ticks, 12-p.W+1)
		}
	})

	t.Run("hash collisions lower only cardinality", func(t *testing.T) {
		clean := SketchParams{M: 2, H: 5, Hash: letterHash}
		colliding := clean
		colliding.Hash = func(b string) uint64 {
			if b == "d" {
				return letterHash("a")
			}
			return letterHash(b)
		}
		minutes := []string{"aaaaabc", "dddddbe"}
		a, b := compose(clean, 1, minutes...), compose(colliding, 1, minutes...)
		if a.LN != b.LN || a.S != 5 || a.LD != 4 || b.S != 4 || b.LD != 3 {
			t.Fatalf("clean %+v, colliding %+v: collisions must lower s and L_D only", a, b)
		}
		exactN, exactD := exactOfArrivals(minutes, 1)
		checkComposition(t, b, exactN, exactD, 1, colliding.M)
	})

}

// bindingHashVector is the keyed hash of b-0000000000000001 under seed 1.
const bindingHashVector = 0xf3b188f84043db1c

func TestBindingHashIsKeyed(t *testing.T) {
	const binding = "b-0000000000000001"
	a, b := SketchParams{Seed: 1}, SketchParams{Seed: 2}
	if a.hash(binding) == b.hash(binding) {
		t.Fatal("the seed does not key the binding hash")
	}
	// Pins the construction: HMAC-SHA256 under the big-endian seed over a
	// purpose label, a zero byte and the binding, first eight bytes.
	if got := a.hash(binding); got != bindingHashVector {
		t.Fatalf("hash = %#016x, want %#016x", got, uint64(bindingHashVector))
	}
}
