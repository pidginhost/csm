package crawlreplay

import (
	"encoding/binary"
	"hash/fnv"
	"slices"
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

func (p SketchParams) hash(binding string) uint64 {
	if p.Hash != nil {
		return p.Hash(binding)
	}
	h := fnv.New64a()
	var seed [8]byte
	binary.BigEndian.PutUint64(seed[:], p.Seed)
	h.Write(seed[:])
	h.Write([]byte(binding))
	return h.Sum64()
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
	// Replace the minimum counter; ties go to the lowest index so replays
	// are deterministic for one arrival order.
	low := 0
	for i := range s.entries {
		if s.entries[i].count < s.entries[low].count {
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

func (k *keySketch) add(p SketchParams, binding string) {
	k.bound++
	k.ss.add(binding)
	k.hs.add(p.hash(binding))
}

// sketchBounds composes W minute summaries into the conservative residual
// bounds of spec 6.3: L_N = max(0, N - T_U) and L_D = max(0, s - K). The
// union is recomputed from whole minutes; nothing is subtracted.
func sketchBounds(minutes []*keySketch, k, h int) (ln, ld int64) {
	var n, bSum int64
	upper := map[string]int64{}
	floors := make([]int64, len(minutes))
	for j, ks := range minutes {
		n += ks.bound
		floors[j] = ks.ss.floor()
		bSum += floors[j]
		for _, e := range ks.ss.entries {
			upper[e.binding] = 0
		}
	}
	for j, ks := range minutes {
		present := make(map[string]int64, len(ks.ss.entries))
		for _, e := range ks.ss.entries {
			present[e.binding] = e.count
		}
		for binding := range upper {
			if c, ok := present[binding]; ok {
				upper[binding] += c
			} else {
				upper[binding] += floors[j]
			}
		}
	}
	us := make([]int64, 0, len(upper)+k)
	for _, u := range upper {
		us = append(us, u)
	}
	for len(us) < k {
		us = append(us, bSum)
	}
	slices.Sort(us)
	var top int64
	for i := len(us) - 1; i >= len(us)-k; i-- {
		top += us[i]
	}
	var union []uint64
	for _, ks := range minutes {
		union = append(union, ks.hs.hashes...)
	}
	slices.Sort(union)
	union = slices.Compact(union)
	s := min(len(union), h)
	return max(0, n-top), int64(max(0, s-k))
}
