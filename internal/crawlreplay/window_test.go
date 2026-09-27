package crawlreplay

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
)

func minuteOf(bindings map[string]int64, unbound int64) *minuteCounts {
	m := newMinuteCounts()
	for b, n := range bindings {
		for range n {
			m.add(&Record{Binding: b})
		}
	}
	for range unbound {
		m.add(&Record{})
	}
	return m
}

func TestWindowResidualExact(t *testing.T) {
	w := newWindow()
	w.apply(minuteOf(map[string]int64{"a": 10, "b": 5, "c": 1, "d": 1}, 4), 1)
	for _, tc := range []struct {
		k             int
		requests, ids int64
	}{
		{0, 17, 4}, {1, 7, 3}, {2, 2, 2}, {4, 0, 0}, {9, 0, 0},
	} {
		if req, ids := w.Residual(tc.k); req != tc.requests || ids != tc.ids {
			t.Errorf("Residual(%d) = %d,%d want %d,%d", tc.k, req, ids, tc.requests, tc.ids)
		}
	}
	if w.Total() != 21 || w.Bound() != 17 {
		t.Fatalf("total=%d bound=%d, want 21 and 17", w.Total(), w.Bound())
	}
}

func TestWindowApplyRemovesMinutesExactly(t *testing.T) {
	w := newWindow()
	first := minuteOf(map[string]int64{"a": 3, "b": 1}, 1)
	second := minuteOf(map[string]int64{"b": 2, "c": 1}, 0)
	w.apply(first, 1)
	w.apply(second, 1)
	w.apply(first, -1)
	if req, ids := w.Residual(0); req != 3 || ids != 2 || w.Total() != 3 {
		t.Fatalf("after expiry residual=%d,%d total=%d", req, ids, w.Total())
	}
	w.apply(second, -1)
	if len(w.bindings) != 0 || len(w.labels) != 0 || w.Total() != 0 {
		t.Fatalf("empty window keeps state: %+v", w)
	}
}

// bruteResidual recomputes the residual from the definition.
func bruteResidual(counts map[string]int64, k int) (int64, int64) {
	var all []int64
	var bound int64
	for _, c := range counts {
		all = append(all, c)
		bound += c
	}
	slices.SortFunc(all, func(a, b int64) int { return int(b - a) })
	var top int64
	for i := 0; i < k && i < len(all); i++ {
		top += all[i]
	}
	return bound - top, int64(max(0, len(all)-k))
}

func TestWindowResidualMatchesDefinition(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for trial := range 500 {
		counts := map[string]int64{}
		for i := range rng.IntN(40) {
			counts[fmt.Sprint("b", i)] = int64(1 + rng.IntN(30))
		}
		w := newWindow()
		w.apply(minuteOf(counts, int64(rng.IntN(5))), 1)
		k := rng.IntN(12)
		gotReq, gotIDs := w.Residual(k)
		wantReq, wantIDs := bruteResidual(counts, k)
		if gotReq != wantReq || gotIDs != wantIDs {
			t.Fatalf("trial %d k=%d: got %d,%d want %d,%d", trial, k, gotReq, gotIDs, wantReq, wantIDs)
		}
	}
}

// Adding traffic from any source never lowers the exact residuals.
func TestWindowResidualMonotoneUnderPadding(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	for trial := range 300 {
		counts := map[string]int64{}
		for i := range 1 + rng.IntN(30) {
			counts[fmt.Sprint("b", i)] = int64(1 + rng.IntN(20))
		}
		k := 1 + rng.IntN(8)
		w := newWindow()
		w.apply(minuteOf(counts, 0), 1)
		beforeReq, beforeIDs := w.Residual(k)
		pad := map[string]int64{fmt.Sprint("heavy", rng.IntN(3)): int64(1 + rng.IntN(500))}
		w.apply(minuteOf(pad, 0), 1)
		afterReq, afterIDs := w.Residual(k)
		if afterReq < beforeReq || afterIDs < beforeIDs {
			t.Fatalf("trial %d: padding lowered residual %d,%d -> %d,%d", trial, beforeReq, beforeIDs, afterReq, afterIDs)
		}
	}
}
