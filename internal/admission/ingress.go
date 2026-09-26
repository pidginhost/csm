package admission

import (
	"fmt"
	"sync"
	"time"
)

// Submission is the response kind, target and producer-minted evidence.
type Submission struct {
	Kind     Kind
	Target   Target
	Evidence Evidence
}

// IngressCheckpoint records the ingress decisions preceding a drain. Counters
// are a canonical QueueCounters record, copied at the handoff boundary.
// They count in-memory decisions, not durable candidate acceptance.
type IngressCheckpoint struct {
	Generation uint64
	Sequence   uint64
	Cursors    QueueCursors
	Counters   []byte
}

// QueueSnapshot is an immutable owner publication. Revision orders committed
// database snapshots; Checkpoint acknowledges only the decisions it contains.
type QueueSnapshot struct {
	Now        time.Time
	Inventory  *Inventory
	Items      []QueueItem
	Cursors    QueueCursors
	Revision   int
	Generation uint64
	Checkpoint *IngressCheckpoint
}

// IngressItem is an accepted submission waiting for the owner. Reports and
// Dropped are the unacknowledged tail frozen by Take.
type IngressItem struct {
	Submission  Submission
	Reports     []string
	Dropped     uint32
	ReportsOnly bool
	key         string
}

// IngressStats counts in-memory decisions. Its counters are checkpointed;
// accepted and duplicate totals and the Critical latch are process-local.
type IngressStats struct {
	Accepted     uint64
	Duplicates   uint64
	Counters     QueueCounters
	CriticalLost uint64
}

type pending struct {
	item       IngressItem
	pos        QueueItem
	taken      bool
	ackReports int
	ackDropped uint32
}

// Ingress holds at most IngressPositions items per partition. Stored work
// cannot borrow this allocation, including while a commit awaits completion.
// Submit takes only the ingress mutex and never calls a ledger method.
type Ingress struct {
	reg         *Registry
	mu          sync.Mutex
	snap        *QueueSnapshot
	view        *QueueView
	items       []*pending
	byKey       map[string]*pending
	byEvidence  map[EvidenceID]*pending
	seq         uint64
	stats       IngressStats
	cursors     QueueCursors
	generation  uint64
	revision    int
	initialized bool
}

func NewIngress(reg *Registry) (*Ingress, error) {
	if reg == nil || !reg.Sealed() {
		return nil, fmt.Errorf("ingress needs a sealed producer registry")
	}
	return &Ingress{reg: reg, byKey: map[string]*pending{}, byEvidence: map[EvidenceID]*pending{}}, nil
}

func (in *Ingress) lose(event QueueEvent, reason Reason, tier Tier, sev Severity) {
	_ = in.stats.Counters.Add(CountKey{Event: event, Reason: reason, Class: tier.Class, Severity: tier.Severity})
	if sev == SeverityCritical {
		in.stats.CriticalLost++
	}
}

// Submit acknowledges memory acceptance only. An equal evidence record merges;
// a later finding is retained even while the owner persists an earlier tail.
func (in *Ingress) Submit(s Submission) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.seq++
	e := s.Evidence
	refused := func(err error, tier Tier) error {
		reason, _ := ReasonOf(err)
		in.lose(EventRefused, reason, tier, e.Severity())
		return err
	}
	if in.snap == nil {
		return refused(refuse(ReasonEngineUnavailable, "the ledger owner has published no queue snapshot"), Tier{})
	}
	if err := in.reg.Validate(e); err != nil {
		return refused(err, Tier{})
	}
	if err := ValidateKindTarget(s.Kind, s.Target); err != nil {
		return refused(err, Tier{})
	}
	// Validate the submission envelope before merging by evidence identity.
	if s.Target != e.Target() {
		return refused(refuse(ReasonInvalid, "submission target differs from evidence"), Tier{})
	}
	if held := in.byEvidence[e.ID()]; held != nil {
		if held.item.Submission.Kind != s.Kind {
			return refused(refuse(ReasonInvalid, "submission differs from held response"), Tier{})
		}
		switch {
		case held.item.Submission.Evidence.Equal(e):
			in.stats.Duplicates++
		case held.item.Submission.Evidence.SameExceptFinding(e):
			in.stats.Duplicates++
			held.addReport(e.FindingID())
		default:
			return refused(ErrEvidenceConflict, Tier{})
		}
		return nil
	}
	a, err := Assess(s.Target, []Evidence{e}, in.snap.Now)
	if err != nil {
		return refused(err, Tier{})
	}
	scope, eligible := Scope{Owner: e.Owner(), Effect: s.Kind.Effect()}, a.Reserved()
	if in.snap.Inventory == nil || !in.snap.Inventory.Current(scope.Owner) {
		scope.Owner, eligible = HostOwner(), false
	}
	p := &pending{item: IngressItem{Submission: s, key: fmt.Sprintf("in:%020d", in.seq)}}
	p.pos = QueueItem{Key: p.item.key, Scope: scope.Key(), Tier: a.Tier, Eligible: eligible, Queued: in.snap.Now, Seq: in.seq}
	placed, ok := in.view.Admit(p.pos)
	in.cursors = in.view.Cursors()
	if !ok {
		return refused(refuse(ReasonQueueOverflow, "queue has no position for the submission"), a.Tier)
	}
	p.pos.Partition = placed.Partition
	if placed.Displaced {
		victim := in.byKey[placed.Victim.Key]
		in.drop(victim)
		in.lose(EventEnded, ReasonQueueOverflow, victim.pos.Tier, victim.item.Submission.Evidence.Severity())
	}
	in.items = append(in.items, p)
	in.byKey[p.item.key] = p
	in.byEvidence[e.ID()] = p
	in.stats.Accepted++
	return nil
}

func (p *pending) addReport(finding string) {
	for _, have := range p.item.Reports {
		if have == finding {
			return
		}
	}
	if len(p.item.Reports) < MaxReportLinks {
		p.item.Reports = append(p.item.Reports, finding)
	} else if p.item.Dropped != ^uint32(0) {
		p.item.Dropped++
	}
}

func (in *Ingress) drop(p *pending) {
	delete(in.byKey, p.item.key)
	delete(in.byEvidence, p.item.Submission.Evidence.ID())
	for i, have := range in.items {
		if have == p {
			in.items = append(in.items[:i], in.items[i+1:]...)
			break
		}
	}
}

// Publish cannot overwrite newer local decisions or a newer durable snapshot.
// A new generation uses a new Ingress; retained work never crosses generations.
func (in *Ingress) Publish(snap *QueueSnapshot) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.publish(snap)
}

func (in *Ingress) publish(snap *QueueSnapshot) {
	if snap == nil {
		in.snap = nil
		return
	}
	if in.initialized && (snap.Generation != in.generation || snap.Revision < in.revision) {
		return
	}
	if !in.initialized {
		in.generation = snap.Generation
		if cp := snap.Checkpoint; cp != nil {
			in.cursors = cp.Cursors
			// Generations retain lifetime counters and the last cursor, but start
			// a new sequence. A same-generation restart resumes the checkpoint.
			if cp.Generation == snap.Generation {
				in.seq = max(in.seq, cp.Sequence)
			}
			counts, err := UnmarshalQueueCounters(cp.Counters)
			if err != nil {
				return
			}
			for k, n := range counts.counts {
				before := in.stats.Counters.Count(k)
				if in.stats.Counters.counts == nil {
					in.stats.Counters.counts = map[CountKey]uint64{}
				}
				in.stats.Counters.counts[k] = n + min(before, ^uint64(0)-n)
			}
		}
		in.initialized = true
	}
	counts := [partitionEnd]int{}
	for _, it := range snap.Items {
		if !it.Partition.Valid() {
			in.snap = nil
			return
		}
		counts[it.Partition]++
		if counts[it.Partition] > it.Partition.DurableCapacity() {
			in.snap = nil
			return
		}
	}
	own := *snap
	own.Items = append([]QueueItem(nil), snap.Items...)
	in.snap, in.revision = &own, snap.Revision
	in.rebuild()
}

// Durable victims remain present and fixed. The view's capacity is the
// durable occupancy plus its transfer allocation, so pressure can replace
// only held work from an over-share scope or a strictly lower own tier.
func (in *Ingress) rebuild() {
	if in.snap == nil {
		return
	}
	v := NewQueueView(in.cursors)
	for p := PartitionGeneral; p < partitionEnd; p++ {
		v.limits[p] = IngressPositions
	}
	for _, it := range in.snap.Items {
		it.Fixed = true
		_ = v.Add(it)
		v.limits[it.Partition]++
	}
	for _, p := range in.items {
		pos := p.pos
		pos.Fixed = p.taken || p.item.ReportsOnly
		_ = v.Add(pos)
	}
	in.view = v
}

// Take freezes an owned copy of each unacknowledged report tail. Taken work
// retains transfer capacity until commit and acknowledgement both finish.
func (in *Ingress) Take(n int) []IngressItem {
	in.mu.Lock()
	defer in.mu.Unlock()
	var out []IngressItem
	for _, p := range in.items {
		if len(out) >= n {
			break
		}
		if p.taken {
			continue
		}
		p.taken = true
		it := p.item
		it.Reports = append([]string(nil), p.item.Reports[p.ackReports:]...)
		it.Dropped = p.item.Dropped - p.ackDropped
		out = append(out, it)
	}
	in.rebuild()
	return out
}

func (in *Ingress) Release(items []IngressItem) {
	in.mu.Lock()
	defer in.mu.Unlock()
	for _, it := range items {
		if p := in.byKey[it.key]; p != nil {
			p.taken = false
		}
	}
	in.rebuild()
}

// Complete acknowledges only the taken tail. Reports accepted during the
// commit remain held for a report-only transaction and cannot create work.
func (in *Ingress) Complete(items []IngressItem, snap *QueueSnapshot) {
	in.mu.Lock()
	defer in.mu.Unlock()
	for _, it := range items {
		if p := in.byKey[it.key]; p != nil && p.taken {
			p.ackReports += len(it.Reports)
			p.ackDropped += it.Dropped
			if p.ackReports < len(p.item.Reports) || p.ackDropped < p.item.Dropped {
				p.taken = false
				p.item.ReportsOnly = true
			} else {
				in.drop(p)
			}
		}
	}
	if snap == nil {
		in.revision++
	}
	in.publish(snap)
	in.rebuild()
}

// Checkpoint copies the current cursor and fixed-dimensional counts. A
// failed transaction never acknowledges it; later submissions keep advancing.
func (in *Ingress) Checkpoint() IngressCheckpoint {
	in.mu.Lock()
	defer in.mu.Unlock()
	counts, _ := in.stats.Counters.MarshalBinary()
	return IngressCheckpoint{Generation: in.generation, Sequence: in.seq, Cursors: in.cursors, Counters: counts}
}

func (in *Ingress) Len() int {
	in.mu.Lock()
	defer in.mu.Unlock()
	return len(in.items)
}

func (in *Ingress) Stats() IngressStats {
	in.mu.Lock()
	defer in.mu.Unlock()
	out := in.stats
	out.Counters = QueueCounters{counts: make(map[CountKey]uint64, len(in.stats.Counters.counts))}
	for k, n := range in.stats.Counters.counts {
		out.Counters.counts[k] = n
	}
	return out
}
