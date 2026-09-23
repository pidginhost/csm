package webui

import (
	"sync"
	"time"
)

// Results computed from a window of recent history are reused between polls.
// A result is kept while history is unchanged, for at most memoMaxAge so time
// windows keep moving on a quiet host; when history changes it is recomputed,
// but not more often than memoMinAge, so a busy host walks history at most
// once per memoMinAge however many dashboards are open. Vars so tests can
// force a recompute.
var (
	memoMinAge = 15 * time.Second
	memoMaxAge = time.Minute
)

// historyMemo holds one memoised result. Concurrent callers of a stale
// result share one computation.
type historyMemo struct {
	mu       sync.Mutex
	valid    bool
	mark     string
	at       time.Time
	value    any
	computes int // how many times value was computed; read by tests
}

func (m *historyMemo) get(mark string, compute func() any) any {
	m.mu.Lock()
	defer m.mu.Unlock()
	age := time.Since(m.at)
	if m.valid && age < memoMaxAge && (mark == m.mark || age < memoMinAge) {
		return m.value
	}
	m.value = compute()
	m.computes++
	m.mark = mark
	m.at = time.Now()
	m.valid = true
	return m.value
}

// historyMemos is a small keyed set of memos for results that depend on
// request parameters, such as the email date range. The oldest entry is
// dropped when the set is full.
type historyMemos struct {
	mu    sync.Mutex
	items map[string]*historyMemo
	order []string
}

const historyMemosMax = 32

func (ms *historyMemos) memo(key string) *historyMemo {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if m, ok := ms.items[key]; ok {
		return m
	}
	if ms.items == nil {
		ms.items = map[string]*historyMemo{}
	}
	if len(ms.order) >= historyMemosMax {
		delete(ms.items, ms.order[0])
		ms.order = ms.order[1:]
	}
	m := &historyMemo{}
	ms.items[key] = m
	ms.order = append(ms.order, key)
	return m
}
