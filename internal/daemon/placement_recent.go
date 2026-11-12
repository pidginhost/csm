package daemon

import (
	"container/list"
	"slices"
	"sync"
	"time"
)

const (
	recentAnalysisCap = 65536
	recentAnalysisTTL = 10 * time.Minute
)

// analysisKey identifies one analysis of one file version. A rename keeps
// dev, inode, size, mtime, mode and owner; Class holds everything else the
// analysis outcome depends on, so a key match means the same analysis
// already ran.
type analysisKey struct {
	Dev, Ino      uint64
	Size, MtimeNs int64
	Mode          uint32
	Uid, Gid      uint32
	Class         string
}

type analysedInode struct{ dev, ino uint64 }

// recentAnalyses remembers files analysed in the last ttl. Losing an entry
// to capacity, expiry or invalidation only costs a second analysis, never a
// skip.
type recentAnalyses struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	order    *list.List // of *recentAnalysis, most recently recorded first
	byKey    map[analysisKey]*list.Element
	byFile   map[analysedInode][]*list.Element

	// seq counts invalidations. invalidated holds the last one per inode,
	// and floor is the newest one no longer held there, so a record begun
	// before floor cannot be checked and is dropped.
	seq         uint64
	floor       uint64
	invalidated map[analysedInode]uint64
}

type recentAnalysis struct {
	key analysisKey
	at  time.Time
}

func newRecentAnalyses(capacity int, ttl time.Duration) *recentAnalyses {
	r := &recentAnalyses{capacity: capacity, ttl: ttl}
	r.reset()
	return r
}

func (r *recentAnalyses) reset() {
	r.order = list.New()
	r.byKey = make(map[analysisKey]*list.Element)
	r.byFile = make(map[analysedInode][]*list.Element)
	r.floor = r.seq
	r.invalidated = make(map[analysedInode]uint64)
}

// Begin marks the start of an analysis; pass the result to Record.
func (r *recentAnalyses) Begin() uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seq
}

// Record notes an analysis that started at begun and has completed. It is
// dropped when the inode was invalidated after begun: the analysis may have
// read content older than the write that invalidated it. A nil receiver
// records nothing.
func (r *recentAnalyses) Record(k analysisKey, begun uint64, now time.Time) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if begun < r.floor || r.invalidated[analysedInode{k.Dev, k.Ino}] > begun {
		return
	}
	if el, ok := r.byKey[k]; ok {
		el.Value.(*recentAnalysis).at = now
		r.order.MoveToFront(el)
		return
	}
	el := r.order.PushFront(&recentAnalysis{key: k, at: now})
	r.byKey[k] = el
	id := analysedInode{k.Dev, k.Ino}
	r.byFile[id] = append(r.byFile[id], el)
	if r.order.Len() > r.capacity {
		r.removeLocked(r.order.Back())
	}
}

// Seen reports whether k was recorded less than ttl before now.
func (r *recentAnalyses) Seen(k analysisKey, now time.Time) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	el, ok := r.byKey[k]
	if !ok {
		return false
	}
	if now.Sub(el.Value.(*recentAnalysis).at) < r.ttl {
		return true
	}
	r.removeLocked(el)
	return false
}

// Invalidate forgets every analysis of the inode: its content may have
// changed in a way the key cannot see.
func (r *recentAnalyses) Invalidate(dev, ino uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id := analysedInode{dev, ino}
	for _, el := range r.byFile[id] {
		r.order.Remove(el)
		delete(r.byKey, el.Value.(*recentAnalysis).key)
	}
	delete(r.byFile, id)
	r.seq++
	if len(r.invalidated) >= r.capacity {
		r.floor, r.invalidated = r.seq-1, make(map[analysedInode]uint64)
	}
	r.invalidated[id] = r.seq
}

// Purge forgets everything.
func (r *recentAnalyses) Purge() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	r.reset()
}

func (r *recentAnalyses) removeLocked(el *list.Element) {
	k := el.Value.(*recentAnalysis).key
	r.order.Remove(el)
	delete(r.byKey, k)
	id := analysedInode{k.Dev, k.Ino}
	if rest := slices.DeleteFunc(r.byFile[id], func(e *list.Element) bool { return e == el }); len(rest) > 0 {
		r.byFile[id] = rest
	} else {
		delete(r.byFile, id)
	}
}
