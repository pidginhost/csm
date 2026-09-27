package crawlreplay

import (
	"fmt"
	"maps"
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

func TestWindowLabelsAndSnapshots(t *testing.T) {
	first, second := newMinuteCounts(), newMinuteCounts()
	for _, r := range []Record{
		{Binding: "a", Label: LabelAttack, Episode: "one"},
		{Binding: "a", Label: LabelAttack, Episode: "one"},
		{Binding: "b", Label: LabelHealthy},
		{},
	} {
		first.add(&r)
	}
	for _, r := range []Record{
		{Label: LabelAttack, Episode: "one"},
		{Binding: "a", Label: LabelAttack, Episode: "two"},
		{Binding: "c", Label: LabelOverload, Episode: "one"},
		{Label: LabelHealthy},
	} {
		second.add(&r)
	}
	w := newWindow()
	w.apply(first, 1)
	w.apply(second, 1)
	want := map[string]int64{
		"": 1, "healthy": 2, "attack/one": 3, "attack/two": 1, "overload/one": 1,
	}
	snapshot := w.Labels()
	if !maps.Equal(snapshot, want) || w.Total() != 8 || w.Bound() != 5 {
		t.Fatalf("labels=%v total=%d bound=%d, want %v, 8, 5", snapshot, w.Total(), w.Bound(), want)
	}
	w.apply(first, -1)
	wantSecond := map[string]int64{
		"healthy": 1, "attack/one": 1, "attack/two": 1, "overload/one": 1,
	}
	if got := w.Labels(); !maps.Equal(got, wantSecond) || w.Total() != 4 || w.Bound() != 2 {
		t.Fatalf("after expiry labels=%v total=%d bound=%d, want %v, 4, 2", got, w.Total(), w.Bound(), wantSecond)
	}
	if !maps.Equal(snapshot, want) {
		t.Fatalf("expiry mutated the earlier snapshot: %v, want %v", snapshot, want)
	}
	snapshot = w.Labels()
	delete(snapshot, "healthy")
	snapshot["attack/one"] = 0
	snapshot["attack/three"] = 1
	if got := w.Labels(); !maps.Equal(got, wantSecond) {
		t.Fatalf("editing a snapshot mutated the window: %v, want %v", got, wantSecond)
	}
	w.apply(second, -1)
	if got := w.Labels(); len(got) != 0 || w.Total() != 0 || w.Bound() != 0 {
		t.Fatalf("expired window labels=%v total=%d bound=%d", got, w.Total(), w.Bound())
	}
}

func TestWindowResidualAcrossMinutes(t *testing.T) {
	first := minuteOf(map[string]int64{"a": 5, "b": 2, "c": 1}, 2)
	second := minuteOf(map[string]int64{"a": 1, "b": 5, "d": 2}, 1)
	third := minuteOf(map[string]int64{"a": 6, "c": 2}, 0)
	w := newWindow()
	for _, tc := range []struct {
		name      string
		minute    *minuteCounts
		sign      int64
		total     int64
		residuals []int64
	}{
		{"empty", newMinuteCounts(), 1, 0, []int64{0}},
		{"first", first, 1, 10, []int64{8, 3, 1, 0}},
		{"second", second, 1, 19, []int64{16, 9, 3, 1, 0}},
		{"expire first", first, -1, 9, []int64{8, 3, 1, 0}},
		{"idle", newMinuteCounts(), 1, 9, []int64{8, 3, 1, 0}},
		{"third", third, 1, 17, []int64{16, 9, 4, 2, 0}},
		{"expire second", second, -1, 8, []int64{8, 2, 0}},
		{"expire third", third, -1, 0, []int64{0}},
		{"reuse first", first, 1, 10, []int64{8, 3, 1, 0}},
	} {
		w.apply(tc.minute, tc.sign)
		if w.Total() != tc.total || w.Bound() != tc.residuals[0] {
			t.Fatalf("%s: total=%d bound=%d, want %d, %d", tc.name, w.Total(), w.Bound(), tc.total, tc.residuals[0])
		}
		for k, wantReq := range tc.residuals {
			wantIDs := int64(len(tc.residuals) - 1 - k)
			if req, ids := w.Residual(k); req != wantReq || ids != wantIDs {
				t.Fatalf("%s: Residual(%d)=%d,%d, want %d,%d", tc.name, k, req, ids, wantReq, wantIDs)
			}
		}
		if req, ids := w.Residual(len(tc.residuals)); req != 0 || ids != 0 {
			t.Fatalf("%s: removing more bindings than present left %d,%d", tc.name, req, ids)
		}
	}
}

func TestWindowResidualPaddingSources(t *testing.T) {
	for _, tc := range []struct {
		name, binding string
		requests, ids int64
	}{
		{"heavy", "a", 3, 2},
		{"light becomes heavy", "c", 7, 2},
		{"new", "d", 8, 3},
		{"unbound", "", 3, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWindow()
			w.apply(minuteOf(map[string]int64{"a": 5, "b": 2, "c": 1}, 0), 1)
			pad := minuteOf(map[string]int64{tc.binding: 6}, 0)
			w.apply(pad, 1)
			if req, ids := w.Residual(1); req != tc.requests || ids != tc.ids {
				t.Fatalf("padded residual=%d,%d, want %d,%d", req, ids, tc.requests, tc.ids)
			}
			w.apply(pad, -1)
			if req, ids := w.Residual(1); req != 3 || ids != 2 || w.Total() != 8 || w.Bound() != 8 {
				t.Fatalf("expiry residual=%d,%d total=%d bound=%d, want 3,2,8,8", req, ids, w.Total(), w.Bound())
			}
		})
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
