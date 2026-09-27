package crawlreplay

import (
	"slices"
)

// minuteCounts is one key's traffic in one covered minute.
type minuteCounts struct {
	bindings map[string]int64 // requests per client binding
	total    int64            // all requests, bound or not
	labels   map[string]int64 // requests per label key (see labelKey)
}

func newMinuteCounts() *minuteCounts {
	return &minuteCounts{bindings: map[string]int64{}, labels: map[string]int64{}}
}

func (m *minuteCounts) add(r *Record) {
	m.total++
	if r.Binding != "" {
		m.bindings[r.Binding]++
	}
	m.labels[labelKey(r.Label, r.Episode)]++
}

// labelKey folds a record's label and episode into one counter name.
func labelKey(label, episode string) string {
	if episode == "" {
		return label
	}
	return label + "/" + episode
}

// Window is the exact traffic of one key over its last W covered minutes.
type Window struct {
	bindings map[string]int64
	total    int64
	labels   map[string]int64
}

func newWindow() *Window {
	return &Window{bindings: map[string]int64{}, labels: map[string]int64{}}
}

// apply adds (sign 1) or removes (sign -1) one minute's counts.
func (w *Window) apply(m *minuteCounts, sign int64) {
	w.total += sign * m.total
	for b, n := range m.bindings {
		if v := w.bindings[b] + sign*n; v != 0 {
			w.bindings[b] = v
		} else {
			delete(w.bindings, b)
		}
	}
	for l, n := range m.labels {
		if v := w.labels[l] + sign*n; v != 0 {
			w.labels[l] = v
		} else {
			delete(w.labels, l)
		}
	}
}

// Total is every request in the window, with or without a binding.
func (w *Window) Total() int64 { return w.total }

// Bound is the requests that carry a client binding.
func (w *Window) Bound() int64 {
	var n int64
	for _, c := range w.bindings {
		n += c
	}
	return n
}

// Residual returns the exact requests and distinct bindings left after
// removing the k largest bindings, or every binding if fewer exist.
// Requests without a binding are not residual evidence: they could all
// belong to one heavy source.
func (w *Window) Residual(k int) (requests, bindings int64) {
	counts := make([]int64, 0, len(w.bindings))
	var bound int64
	for _, c := range w.bindings {
		counts = append(counts, c)
		bound += c
	}
	slices.Sort(counts)
	var top int64
	for i := len(counts) - 1; i >= 0 && len(counts)-i <= k; i-- {
		top += counts[i]
	}
	return bound - top, max(0, int64(len(counts)-k))
}

// Labels returns a copy of the window's per-label request counts.
func (w *Window) Labels() map[string]int64 {
	out := make(map[string]int64, len(w.labels))
	for l, n := range w.labels {
		out[l] = n
	}
	return out
}
