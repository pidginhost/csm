package admission

import (
	"fmt"
	"sort"
	"time"
)

// Queue bounds of spec 5.6. Ingress, queued and in-flight candidates share
// them. Every candidate record is at most MaxCandidateBytes, so the 4 MiB
// payload bound of the spec cannot bind before the count does.
const (
	// QueueCapacity bounds ingress, queued and in-flight candidates together.
	QueueCapacity = 1000
	// ReservedPositions of the capacity are held for candidates that may use
	// the reserved lane: direct compromise or independent corroboration.
	ReservedPositions = 200
	// IngressPositions reserves transfer space within each partition.
	IngressPositions = 64
)

// Partition is the part of the queue a candidate holds its position in.
// Values are persisted: append, never renumber.
type Partition uint8

const (
	PartitionGeneral Partition = iota + 1
	// PartitionReserved takes only candidates eligible for the reserved
	// lane. General work never displaces it.
	PartitionReserved
	partitionEnd
)

var partitionNames = [...]string{"", "general", "reserved"}

func (p Partition) Valid() bool { return p >= PartitionGeneral && p < partitionEnd }

func (p Partition) String() string {
	if p.Valid() {
		return partitionNames[p]
	}
	return fmt.Sprintf("partition(%d)", uint8(p))
}

// Capacity is how many positions p holds.
func (p Partition) Capacity() int {
	if p == PartitionReserved {
		return ReservedPositions
	}
	return QueueCapacity - ReservedPositions
}

// DurableCapacity leaves room for an ingress group even when durable work
// fills the partition. In-flight candidates retain durable positions.
func (p Partition) DurableCapacity() int { return p.Capacity() - IngressPositions }

// QueueItem is one queue position as admission sees it.
type QueueItem struct {
	// Key names the item: a candidate ID, or an ingress sequence.
	Key string
	// Scope is the fairness scope key.
	Scope     string
	Partition Partition
	Tier      Tier
	// Eligible: the candidate may hold a reserved position.
	Eligible bool
	// Queued, then Seq, then Key order items from oldest to newest.
	Queued time.Time
	// Seq orders items queued at the same instant. Stored items carry
	// zero; arrivals being decided and ingress items take increasing
	// values, so an arrival is newer than all work already queued.
	Seq uint64
	// Fixed items hold their position but are never displaced: they are in
	// flight or not yet assessed.
	Fixed bool
}

// newer reports whether a joined the queue after b.
func (a QueueItem) newer(b QueueItem) bool {
	if !a.Queued.Equal(b.Queued) {
		return a.Queued.After(b.Queued)
	}
	if a.Seq != b.Seq {
		return a.Seq > b.Seq
	}
	return a.Key > b.Key
}

// goesFirst reports whether a scope that must lose an entry loses a before
// b: the lowest tier first, then the newest.
func goesFirst(a, b QueueItem) bool {
	if a.Tier != b.Tier {
		return a.Tier.Less(b.Tier)
	}
	return a.newer(b)
}

// QueueCursors are the persisted remainder cursors of the two partitions.
// Each is a scope key; the scopes after it take the remainder of an uneven
// share, so admission opportunities rotate when scopes outnumber positions.
type QueueCursors struct {
	General  string
	Reserved string
}

type scopeQueue struct {
	count int
	// victims are the displaceable items, next victim first.
	victims []QueueItem
}

type partitionQueue struct {
	count  int
	cursor string
	scopes map[string]*scopeQueue
}

// QueueView is the occupancy of the queue by partition and scope. Admit
// applies the overflow rules of spec 5.6 to it. It is not safe for
// concurrent use.
type QueueView struct {
	limits [partitionEnd]int
	parts  [partitionEnd]partitionQueue
	items  map[string]QueueItem
}

// NewQueueView returns an empty view with the given cursors.
func NewQueueView(c QueueCursors) *QueueView {
	v := &QueueView{items: map[string]QueueItem{}}
	for p := PartitionGeneral; p < partitionEnd; p++ {
		v.parts[p].scopes = map[string]*scopeQueue{}
		v.limits[p] = p.Capacity()
	}
	v.parts[PartitionGeneral].cursor, v.parts[PartitionReserved].cursor = c.General, c.Reserved
	return v
}

// NewDurableQueueView keeps the transfer allocation unavailable to stored work.
func NewDurableQueueView(c QueueCursors) *QueueView {
	v := NewQueueView(c)
	for p := PartitionGeneral; p < partitionEnd; p++ {
		v.limits[p] = p.DurableCapacity()
	}
	return v
}

// Cursors returns the current remainder cursors.
func (v *QueueView) Cursors() QueueCursors {
	return QueueCursors{General: v.parts[PartitionGeneral].cursor, Reserved: v.parts[PartitionReserved].cursor}
}

// Len is the number of positions held.
func (v *QueueView) Len() int { return len(v.items) }

// Count is the number of positions held in p.
func (v *QueueView) Count(p Partition) int { return v.parts[p].count }

// Room reports whether p has a free position.
func (v *QueueView) Room(p Partition) bool { return v.parts[p].count < v.limits[p] }

// Item returns the item with key k.
func (v *QueueView) Item(k string) (QueueItem, bool) {
	it, ok := v.items[k]
	return it, ok
}

// Add records an item in its partition without applying admission rules:
// it already holds its position.
func (v *QueueView) Add(it QueueItem) error {
	if !it.Partition.Valid() || it.Key == "" || it.Scope == "" {
		return fmt.Errorf("queue item has no partition, key or scope")
	}
	if _, dup := v.items[it.Key]; dup {
		return fmt.Errorf("queue item is already present")
	}
	pq := &v.parts[it.Partition]
	sq := pq.scopes[it.Scope]
	if sq == nil {
		sq = &scopeQueue{}
		pq.scopes[it.Scope] = sq
	}
	sq.count++
	pq.count++
	if !it.Fixed {
		i := sort.Search(len(sq.victims), func(i int) bool { return goesFirst(it, sq.victims[i]) })
		sq.victims = append(sq.victims, QueueItem{})
		copy(sq.victims[i+1:], sq.victims[i:])
		sq.victims[i] = it
	}
	v.items[it.Key] = it
	return nil
}

// Remove releases the position of the item with key k.
func (v *QueueView) Remove(k string) (QueueItem, bool) {
	it, ok := v.items[k]
	if !ok {
		return QueueItem{}, false
	}
	delete(v.items, k)
	pq := &v.parts[it.Partition]
	sq := pq.scopes[it.Scope]
	sq.count--
	pq.count--
	for i := range sq.victims {
		if sq.victims[i].Key == k {
			sq.victims = append(sq.victims[:i], sq.victims[i+1:]...)
			break
		}
	}
	if sq.count == 0 {
		delete(pq.scopes, it.Scope)
	}
	return it, true
}

// Placement is an admission decision: the partition the item joined and
// the item it displaced, if any.
type Placement struct {
	Partition Partition
	Displaced bool
	Victim    QueueItem
}

// Admit decides whether x may take a position and records it. x first
// takes a free position: an eligible item prefers the reserved partition,
// every other item uses the general one. When no position is free, each
// partition x may use is tried in the same order under the fair-share
// rules: a scope at or over its share can only replace its own lowest
// tier, newest entry, and only when that entry goes before x; a scope below
// its share reclaims one position from the scope with the greatest excess.
// Each full-partition decision advances that partition's cursor. A refused
// x changes nothing but the cursors.
func (v *QueueView) Admit(x QueueItem) (Placement, bool) {
	order := []Partition{PartitionGeneral}
	if x.Eligible {
		order = []Partition{PartitionReserved, PartitionGeneral}
	}
	for _, p := range order {
		if v.Room(p) {
			return v.place(x, p, nil), true
		}
	}
	for _, p := range order {
		if victim, ok := v.overflow(x, p); ok {
			return v.place(x, p, &victim), true
		}
	}
	return Placement{}, false
}

func (v *QueueView) place(x QueueItem, p Partition, victim *QueueItem) Placement {
	out := Placement{Partition: p}
	if victim != nil {
		v.Remove(victim.Key)
		out.Displaced, out.Victim = true, *victim
	}
	x.Partition = p
	// x is new to the view and its partition is valid, so Add cannot fail.
	_ = v.Add(x)
	return out
}

// overflow applies the fair-share rules of a full partition to x.
func (v *QueueView) overflow(x QueueItem, p Partition) (QueueItem, bool) {
	pq := &v.parts[p]
	keys := make([]string, 0, len(pq.scopes)+1)
	for k := range pq.scopes {
		keys = append(keys, k)
	}
	if pq.scopes[x.Scope] == nil {
		keys = append(keys, x.Scope)
	}
	sort.Strings(keys)
	n := len(keys)
	start := sort.SearchStrings(keys, pq.cursor)
	if start < n && keys[start] == pq.cursor {
		start++
	}
	start %= n
	rank := make(map[string]int, n)
	for r := 0; r < n; r++ {
		rank[keys[(start+r)%n]] = r
	}
	capacity := v.limits[p]
	share := func(scope string) int {
		if rank[scope] < capacity%n {
			return capacity/n + 1
		}
		return capacity / n
	}
	pq.cursor = keys[start]
	count := func(scope string) int {
		if sq := pq.scopes[scope]; sq != nil {
			return sq.count
		}
		return 0
	}
	if count(x.Scope) >= share(x.Scope) {
		sq := pq.scopes[x.Scope]
		if sq == nil || len(sq.victims) == 0 || !goesFirst(sq.victims[0], x) {
			return QueueItem{}, false
		}
		return sq.victims[0], true
	}
	best, bestExcess := "", 0
	for r := 0; r < n; r++ {
		k := keys[(start+r)%n]
		sq := pq.scopes[k]
		if k == x.Scope || sq == nil || len(sq.victims) == 0 {
			continue
		}
		if excess := sq.count - share(k); excess > bestExcess {
			best, bestExcess = k, excess
		}
	}
	if best == "" {
		return QueueItem{}, false
	}
	return pq.scopes[best].victims[0], true
}
