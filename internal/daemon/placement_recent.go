package daemon

import (
	"container/list"
	"sync"
	"time"
)

const (
	recentAnalysisCap = 65536
	recentAnalysisTTL = 10 * time.Minute
)

// analysisKey identifies one analysis of one file version. A rename keeps
// dev, inode, size and mtime; Class holds everything else the analysis
// outcome depends on, so a key match means the same analysis already ran.
type analysisKey struct {
	Dev, Ino      uint64
	Size, MtimeNs int64
	Class         string
}

// recentAnalyses remembers files analysed in the last ttl. Losing an entry
// to capacity or expiry only costs a second analysis, never a skip.
type recentAnalyses struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	order    *list.List // of *recentAnalysis, most recently recorded first
	byKey    map[analysisKey]*list.Element
}

type recentAnalysis struct {
	key analysisKey
	at  time.Time
}

func newRecentAnalyses(capacity int, ttl time.Duration) *recentAnalyses {
	return &recentAnalyses{
		capacity: capacity, ttl: ttl,
		order: list.New(), byKey: make(map[analysisKey]*list.Element),
	}
}

// Record notes a completed analysis. A nil receiver records nothing.
func (r *recentAnalyses) Record(k analysisKey, now time.Time) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if el, ok := r.byKey[k]; ok {
		el.Value.(*recentAnalysis).at = now
		r.order.MoveToFront(el)
		return
	}
	r.byKey[k] = r.order.PushFront(&recentAnalysis{key: k, at: now})
	if r.order.Len() > r.capacity {
		oldest := r.order.Back()
		r.order.Remove(oldest)
		delete(r.byKey, oldest.Value.(*recentAnalysis).key)
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
	r.order.Remove(el)
	delete(r.byKey, k)
	return false
}
