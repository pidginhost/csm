package crawlreplay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"strings"
)

// SketchParams size the disposable per-minute summaries that phase 1 uses
// to choose m and h. They are prototypes of spec 6.3, not the production
// sketch; plan 1.3 must reproduce these bounds against the same oracle.
type SketchParams struct {
	M    int    `json:"m"`    // Space-Saving counters per key-minute; must exceed K
	H    int    `json:"h"`    // smallest binding hashes kept per key-minute; at least D+K
	Seed uint64 `json:"seed"` // private hash seed
	// Hash overrides the keyed binding hash, for forced-collision tests.
	Hash func(binding string) uint64 `json:"-"`
}

// bindingHashPurpose separates the cardinality hash from any other use of
// the same seed.
const bindingHashPurpose = "crawlreplay binding cardinality v1"

// hash is the keyed binding hash: HMAC-SHA256 under the big-endian seed
// over the purpose label, a zero byte and the binding, first eight bytes.
// An unkeyed hash would let a client choose bindings whose hashes collide
// or sort low and so steer the bottom-h witness.
func (p SketchParams) hash(binding string) uint64 {
	if p.Hash != nil {
		return p.Hash(binding)
	}
	var seed [8]byte
	binary.BigEndian.PutUint64(seed[:], p.Seed)
	m := hmac.New(sha256.New, seed[:])
	m.Write([]byte(bindingHashPurpose))
	m.Write([]byte{0})
	m.Write([]byte(binding))
	return binary.BigEndian.Uint64(m.Sum(nil))
}

type ssEntry struct {
	binding string
	count   int64
	err     int64
}

// spaceSaving is an insertion-only Space-Saving summary with unit weights.
type spaceSaving struct {
	m       int
	entries []ssEntry
	index   map[string]int
}

func newSpaceSaving(m int) *spaceSaving {
	return &spaceSaving{m: m, index: make(map[string]int, m)}
}

func (s *spaceSaving) add(binding string) {
	if i, ok := s.index[binding]; ok {
		s.entries[i].count++
		return
	}
	if len(s.entries) < s.m {
		s.index[binding] = len(s.entries)
		s.entries = append(s.entries, ssEntry{binding: binding, count: 1})
		return
	}
	// Replace the minimum counter. Ties go to the smallest binding, so the
	// choice depends on the counters alone, not on their slice order,
	// which a restored summary does not keep.
	low := 0
	for i := range s.entries {
		e, l := s.entries[i], s.entries[low]
		if e.count < l.count || (e.count == l.count && e.binding < l.binding) {
			low = i
		}
	}
	old := s.entries[low]
	delete(s.index, old.binding)
	s.index[binding] = low
	s.entries[low] = ssEntry{binding: binding, count: old.count + 1, err: old.count}
}

// floor is b_j: the minimum counter when the summary is full, else zero.
// An absent binding's true count in this minute is at most floor.
func (s *spaceSaving) floor() int64 {
	if len(s.entries) < s.m {
		return 0
	}
	low := s.entries[0].count
	for _, e := range s.entries[1:] {
		low = min(low, e.count)
	}
	return low
}

// bottomH keeps the h smallest distinct binding hashes, ascending.
type bottomH struct {
	h      int
	hashes []uint64
}

func (b *bottomH) add(x uint64) {
	i, found := slices.BinarySearch(b.hashes, x)
	if found || (len(b.hashes) == b.h && i == b.h) {
		return
	}
	b.hashes = slices.Insert(b.hashes, i, x)
	if len(b.hashes) > b.h {
		b.hashes = b.hashes[:b.h]
	}
}

// keySketch is one key's summaries for one minute.
type keySketch struct {
	ss    *spaceSaving
	hs    *bottomH
	bound int64 // exact count of bound requests this minute
}

func newKeySketch(p SketchParams) *keySketch {
	return &keySketch{ss: newSpaceSaving(p.M), hs: &bottomH{h: p.H}}
}

func (k *keySketch) add(p SketchParams, binding string) { k.insert(binding, p.hash(binding)) }

// insert counts one request of binding, whose keyed hash is h.
func (k *keySketch) insert(binding string, h uint64) {
	k.bound++
	k.ss.add(binding)
	k.hs.add(h)
}

// sketchWindow is the spec 6.3 composition of one key's W minute summaries.
type sketchWindow struct {
	N     int64            // exact bound requests in the window
	B     int64            // sum of the minute floors: bound for any absent binding
	Upper map[string]int64 // U(x) for every binding some summary retained
	Top   int64            // T_U: the K largest U values, padded with B
	S     int              // distinct retained hashes in the window, at most h
	LN    int64            // max(0, N - T_U)
	LD    int64            // max(0, S - K)
}

// composeSketches composes W minute summaries into the conservative
// residual bounds of spec 6.3. The union is recomputed from whole minutes;
// nothing is subtracted or recompressed.
func composeSketches(minutes []*keySketch, k, h int) sketchWindow {
	w := sketchWindow{Upper: map[string]int64{}}
	floors := make([]int64, len(minutes))
	for j, ks := range minutes {
		w.N += ks.bound
		floors[j] = ks.ss.floor()
		w.B += floors[j]
		for _, e := range ks.ss.entries {
			w.Upper[e.binding] = 0
		}
	}
	for j, ks := range minutes {
		present := make(map[string]int64, len(ks.ss.entries))
		for _, e := range ks.ss.entries {
			present[e.binding] = e.count
		}
		for binding := range w.Upper {
			if c, ok := present[binding]; ok {
				w.Upper[binding] += c
			} else {
				w.Upper[binding] += floors[j]
			}
		}
	}
	us := make([]int64, 0, len(w.Upper)+k)
	for _, u := range w.Upper {
		us = append(us, u)
	}
	for len(us) < k {
		us = append(us, w.B)
	}
	slices.Sort(us)
	for i := len(us) - 1; i >= len(us)-k; i-- {
		w.Top += us[i]
	}
	var union []uint64
	for _, ks := range minutes {
		union = append(union, ks.hs.hashes...)
	}
	slices.Sort(union)
	union = slices.Compact(union)
	w.S = min(len(union), h)
	w.LN, w.LD = max(0, w.N-w.Top), int64(max(0, w.S-k))
	return w
}

// sketchState is a minute summary as a snapshot stores it.
type sketchState struct {
	Bound   int64         `json:"bound"`
	Entries []sketchEntry `json:"entries"` // ordered by binding
	Hashes  []uint64      `json:"hashes"`  // ascending
}

type sketchEntry struct {
	Binding string `json:"b"`
	Count   int64  `json:"c"`
	Err     int64  `json:"e"`
}

func (k *keySketch) state() sketchState {
	st := sketchState{Bound: k.bound, Entries: make([]sketchEntry, 0, len(k.ss.entries)), Hashes: slices.Clone(k.hs.hashes)}
	for _, e := range k.ss.entries {
		st.Entries = append(st.Entries, sketchEntry{Binding: e.binding, Count: e.count, Err: e.err})
	}
	slices.SortFunc(st.Entries, func(a, b sketchEntry) int { return strings.Compare(a.Binding, b.Binding) })
	if st.Hashes == nil {
		st.Hashes = []uint64{}
	}
	return st
}

// restoreSketch rebuilds a summary, refusing one that breaks the
// Space-Saving invariants: counters sum to the bound requests, each
// insertion error is below its counter, and no error exists before the
// summary filled.
func restoreSketch(p SketchParams, st sketchState) (*keySketch, error) {
	if st.Bound < 1 || st.Entries == nil || len(st.Entries) == 0 || len(st.Entries) > p.M ||
		st.Hashes == nil || len(st.Hashes) == 0 || len(st.Hashes) > p.H {
		return nil, ErrSession
	}
	ks := newKeySketch(p)
	var total int64
	for i, e := range st.Entries {
		if e.Binding == "" || (i > 0 && e.Binding <= st.Entries[i-1].Binding) || e.Count < 1 || e.Err < 0 || e.Err >= e.Count ||
			(len(st.Entries) < p.M && e.Err != 0) {
			return nil, ErrSession
		}
		var ok bool
		if total, ok = checkedSum(total, e.Count); !ok {
			return nil, ErrSession
		}
		ks.ss.index[e.Binding] = i
		ks.ss.entries = append(ks.ss.entries, ssEntry{binding: e.Binding, count: e.Count, err: e.Err})
	}
	for i := 1; i < len(st.Hashes); i++ {
		if st.Hashes[i] <= st.Hashes[i-1] {
			return nil, ErrSession
		}
	}
	if total != st.Bound {
		return nil, ErrSession
	}
	ks.bound, ks.hs.hashes = st.Bound, slices.Clone(st.Hashes)
	return ks, nil
}
