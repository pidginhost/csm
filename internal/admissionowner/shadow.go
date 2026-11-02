package admissionowner

import (
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"slices"
	"sort"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// forecastEntries bounds the active blocks one forecast models. It is a
// modelling bound, never a real set limit.
const forecastEntries = firewall.MaxShadowBlocks

// resetReason says why a forecast session started.
type resetReason uint8

const (
	resetStartup resetReason = iota + 1
	resetModeChange
	// resetModelError: the previous session's model could not be metered.
	resetModelError
)

func (r resetReason) String() string {
	switch r {
	case resetStartup:
		return "startup"
	case resetModeChange:
		return "mode_change"
	case resetModelError:
		return "model_error"
	}
	return ""
}

// forecastError is why a forecast could not run or go on, a fixed code
// status shows (spec 3.8).
type forecastError string

const (
	forecastEngineUnavailable forecastError = "engine_unavailable"
	forecastClockDegraded     forecastError = "clock_degraded"
	forecastLedgerUnavailable forecastError = "ledger_unavailable"
	forecastSnapshotMismatch  forecastError = "snapshot_mismatch"
	forecastSessionID         forecastError = "session_id_unavailable"
	forecastInvalidPolicy     forecastError = "invalid_policy"
	// forecastModelError: the session's model could not be metered, so the
	// session was dropped.
	forecastModelError forecastError = "model_error"
)

// newSessionID reads a random 128-bit forecast session ID.
func newSessionID(r io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// shadowEntry is one forecast block: its kind, absolute lease expiry, the
// partition of the set it occupies and its rank.
type shadowEntry struct {
	kind      admission.Kind
	expires   time.Time
	partition admission.Partition
	tier      admission.Tier
	action    admission.ActionID
	target    admission.Target
}

// shadowRank is what ranks a forecast block as a victim (spec 5.6): the
// pick's tier, the action of its next attempt and its address. A block
// without a valid tier is never a victim, and a pick without one replaces
// nothing.
type shadowRank struct {
	tier   admission.Tier
	action admission.ActionID
	target admission.Target
}

// shadowChange is a capacity admission a forecast decided and has not
// installed: one charge and one entry, and the lower-tier block it
// replaces, zero for a free slot.
type shadowChange struct {
	ip     string
	entry  shadowEntry
	charge admission.Charge
	next   admission.CeilingState
	victim admission.EvictionVictim
}

// shadow is one dry-run forecast session. It copies the real ceiling when
// the session starts and then lives apart from it: simulated admissions
// charge only the copy, and the copy is metered by the same committed
// clock deltas as the ledger, never copied again. Only the owner goroutine
// uses it. A restart or a new session starts over from the real state.
type shadow struct {
	id      string
	since   time.Time
	reset   resetReason
	ceiling admission.CeilingState
	// charges are the retained real and simulated charges in the order they
	// leave the window, at most MaxCeiling.
	charges []admission.Charge
	entries map[string]shadowEntry
	picks   [admission.PredictionSlots]uint64
	recent  minuteCounts
	// adm is the occupancy of the last admission snapshot, nil while none
	// could be read; its answers are dropped.
	adm *firewall.BlockAdmission
	// replaced is the imports the session replaced, by name, until their
	// lease expiry: the real set still holds and lists them.
	replaced map[admission.ActionID]time.Time
}

// newShadow starts session id at wall time since from the real ceiling and
// its retained charges, in key order.
func newShadow(id string, since time.Time, reset resetReason, ceiling admission.CeilingState, charges []admission.Charge) (*shadow, error) {
	if raw, err := hex.DecodeString(id); err != nil || len(raw) != 16 || hex.EncodeToString(raw) != id {
		return nil, errors.New("forecast session ID is malformed")
	}
	if ceiling.Limit == 0 || ceiling.Validate() != nil || len(charges) > admission.MaxCeiling {
		return nil, errors.New("forecast needs a valid ceiling with a limit")
	}
	return &shadow{
		id: id, since: since.UTC(), reset: reset, ceiling: ceiling,
		charges: append([]admission.Charge(nil), charges...), entries: map[string]shadowEntry{},
		replaced: map[admission.ActionID]time.Time{},
	}, nil
}

// advance meters one committed clock reading as the ledger does: it credits
// the elapsed time and releases the charges that have left the window,
// oldest first. Release never refunds credit, and wall time alone earns or
// releases nothing.
func (s *shadow) advance(t admission.ClockTick) error {
	next, err := s.ceiling.Advance(t.Elapsed)
	if err != nil {
		return err
	}
	released := 0
	for _, c := range s.charges {
		if !c.Releasable(t.Now, next.Elapsed) {
			break
		}
		if next, err = next.Release(c.Lane, c.Cost); err != nil {
			return err
		}
		released++
	}
	s.ceiling, s.charges = next, s.charges[released:]
	return nil
}

// setLimit applies a new limit without refilling credit. Retained charges
// stay until they age out, even above a reduced limit.
func (s *shadow) setLimit(limit uint32) error {
	next, err := s.ceiling.SetLimit(limit)
	if err != nil {
		return err
	}
	s.ceiling = next
	return nil
}

// expire drops the forecast blocks and replaced imports whose lease has
// ended at lease, a reading of the engine's lease clock.
func (s *shadow) expire(lease time.Time) {
	for ip, e := range s.entries {
		if !lease.Before(e.expires) {
			delete(s.entries, ip)
		}
	}
	for name, expires := range s.replaced {
		if !lease.Before(expires) {
			delete(s.replaced, name)
		}
	}
}

// ips are the forecast addresses, in order, for an admission snapshot to
// count the real blocks of.
func (s *shadow) ips() []string { return slices.Sorted(maps.Keys(s.entries)) }

// covering says how a forecast block holds ip for a pick lasting until
// expires: one that covers it as a real block would, within the engine's
// readback slack, answers it; a shorter one holds the address as live work
// would wait for it. Zero when none holds it.
func (s *shadow) covering(ip string, expires time.Time) admission.Prediction {
	e, ok := s.entries[ip]
	switch {
	case !ok:
		return 0
	case !firewall.CoversExpiry(e.expires, expires):
		return admission.PredictPendingRecovery
	}
	return admission.PredictExistingShadow
}

// occupancy is the modelled temporary set: the real timed occupants, with
// real automatic blocks in the general partition, less the listed imports
// the session replaced, and in their own partitions the forecast blocks
// the real sets do not already hold as a timed or an untimed element. As
// in the ledger, every listed import counts even if the count is lower.
// adm is this turn's snapshot, taken after expire.
func (s *shadow) occupancy(adm firewall.BlockAdmission) admission.SetOccupancy {
	general, reserved := s.counted(adm)
	imported := max(adm.Imported, len(adm.Imports)) - s.replacedListed(adm)
	return admission.SetOccupancy{Limit: adm.Limit, Unclaimed: adm.Unclaimed, General: imported + adm.Admission + general, Reserved: reserved}
}

// counted is the forecast blocks of each partition the real sets do not
// already hold.
func (s *shadow) counted(adm firewall.BlockAdmission) (general, reserved int) {
	for ip, e := range s.entries {
		switch {
		case adm.ShadowHeld[ip]:
		case e.partition == admission.PartitionReserved:
			reserved++
		default:
			general++
		}
	}
	return general, reserved
}

// replacedListed is how many imports adm lists that the session replaced.
// A replaced import the list no longer names counts again in Imported, as
// the forecast cannot tell whether it went or is merely unlisted.
func (s *shadow) replacedListed(adm firewall.BlockAdmission) int {
	n := 0
	for _, imp := range adm.Imports {
		if _, ok := s.replaced[admission.ActionID(imp.ID)]; ok {
			n++
		}
	}
	return n
}

// limits is the modelled set's slot budget, by the rule admission uses:
// its free slots and, once the general partition is full, the victims
// strictly higher work may replace: the ranked forecast blocks the real
// sets do not hold, and the listed imports not already replaced.
func (s *shadow) limits(adm firewall.BlockAdmission) *admission.SlotLimits {
	limits, _ := s.occupancy(adm).Limits(func() ([]admission.EvictionVictim, error) {
		var pool []admission.EvictionVictim
		for ip, e := range s.entries {
			if !adm.ShadowHeld[ip] && e.tier.Valid() && e.partition.Valid() {
				pool = append(pool, admission.EvictionVictim{Action: e.action, Target: e.target, Tier: e.tier, Partition: e.partition, ExpiresAt: e.expires})
			}
		}
		for _, v := range importVictims(adm.Imports) {
			if _, gone := s.replaced[v.Action]; !gone {
				pool = append(pool, v)
			}
		}
		return pool, nil
	})
	return limits
}

// demand is what a pick of kind ranked r on lanes asks of the set, as
// the ledger asks it: only one-unit block_ip work may replace another.
func demand(kind admission.Kind, lanes []admission.Lane, r shadowRank) admission.SlotDemand {
	cost := kind.CeilingCost()
	return admission.SlotDemand{Tier: r.tier, Cost: cost, Evicts: kind == admission.KindBlockIP && cost == 1, Target: r.target,
		Reserved: slices.ContainsFunc(lanes, func(l admission.Lane) bool { return admission.PartitionOf(l) == admission.PartitionReserved })}
}

// full reports whether a block_ip pick ranked r on lanes finds neither a
// free slot in a partition it may occupy nor a strictly lower-tier block
// it may replace. A zero limit is the finite automatic capacity.
func (s *shadow) full(adm firewall.BlockAdmission, lanes []admission.Lane, r shadowRank) bool {
	limits, d := s.limits(adm), demand(admission.KindBlockIP, lanes, r)
	for _, lane := range lanes {
		if _, ok := limits.Room(lane, d); ok {
			return false
		}
	}
	return true
}

// limited reports whether the forecast can model no other active block.
func (s *shadow) limited() bool { return len(s.entries) >= forecastEntries }

// admit decides a ready pick of kind for ip lasting until expires, ranked
// r, at admission time now, against this turn's snapshot: a full set
// first, then the modelling bound, then the ceiling on each of lanes in
// order that has room, the selected lane first. Room is a free slot of the
// lane's partition or, with none, the first strictly lower-tier block in
// eviction order, which the block replaces in that block's partition. A
// block on a free slot occupies the partition of the lane it is charged
// on. Only a capacity admission returns a change; nothing is installed
// until commit. Kinds outside the address model take no capacity.
func (s *shadow) admit(ip string, kind admission.Kind, expires time.Time, lanes []admission.Lane, now time.Time, adm firewall.BlockAdmission, r shadowRank) (admission.Prediction, *shadowChange, error) {
	switch {
	case kind != admission.KindBlockIP:
		return admission.PredictNotModelled, nil, nil
	case s.full(adm, lanes, r):
		return admission.PredictSetFull, nil, nil
	case s.limited():
		return admission.PredictForecastLimited, nil, nil
	}
	limits, d := s.limits(adm), demand(kind, lanes, r)
	cost := kind.CeilingCost()
	for _, lane := range lanes {
		victim, ok := limits.Room(lane, d)
		if !ok {
			continue
		}
		next, err := s.ceiling.Charge(lane, cost)
		if reason, refused := admission.ReasonOf(err); refused && reason == admission.ReasonCeiling {
			continue
		}
		if err != nil {
			return 0, nil, err
		}
		pred, partition := admission.PredictCapacityAdmit, admission.PartitionOf(lane)
		if victim != (admission.EvictionVictim{}) {
			pred, partition = admission.PredictCapacityEvict, victim.Partition
		}
		return pred, &shadowChange{
			ip: ip, entry: shadowEntry{kind: kind, expires: expires, partition: partition, tier: r.tier, action: r.action, target: r.target}, next: next,
			charge: admission.Charge{At: now, Lane: lane, Cost: cost, Elapsed: s.ceiling.Elapsed}, victim: victim,
		}, nil
	}
	return admission.PredictCeiling, nil, nil
}

// commit installs a decision whose ending committed, and counts it at the
// process's monotonic time mono.
func (s *shadow) commit(p admission.Prediction, change *shadowChange, mono time.Time) {
	if change != nil {
		s.ceiling = change.next
		// Imported legacy spend can be dated at the end of the current
		// hour. Keep earlier predictions ahead of it for window release.
		at := sort.Search(len(s.charges), func(i int) bool { return s.charges[i].At.After(change.charge.At) })
		s.charges = slices.Insert(s.charges, at, change.charge)
		// A replaced forecast block leaves the model; a replaced import
		// stays in the real set, so the session remembers it.
		switch v := change.victim; {
		case v == (admission.EvictionVictim{}):
		case admission.ImportedVictim(v.Action):
			s.replaced[v.Action] = v.ExpiresAt
		default:
			addr, _ := v.Target.Addr()
			delete(s.entries, addr.String())
		}
		s.entries[change.ip] = change.entry
	}
	if s.picks[p] != ^uint64(0) {
		s.picks[p]++
	}
	s.recent.add(mono, p)
}

// minuteCounts keeps sixty one-minute buckets of predictions on the
// process's monotonic clock, aligned to the first count, so a wall-clock
// change cannot age them.
type minuteCounts struct {
	base    time.Time
	buckets [60]minuteBucket
}

type minuteBucket struct {
	set    bool
	minute int64
	counts [admission.PredictionSlots]uint64
}

func (m *minuteCounts) minute(mono time.Time) int64 {
	return int64(max(mono.Sub(m.base), 0) / time.Minute)
}

func (m *minuteCounts) add(mono time.Time, p admission.Prediction) {
	if m.base.IsZero() {
		m.base = mono
	}
	minute := m.minute(mono)
	b := &m.buckets[minute%int64(len(m.buckets))]
	if !b.set || b.minute != minute {
		*b = minuteBucket{set: true, minute: minute}
	}
	if b.counts[p] != ^uint64(0) {
		b.counts[p]++
	}
}

// total sums the sixty minutes up to and including mono's.
func (m *minuteCounts) total(mono time.Time) [admission.PredictionSlots]uint64 {
	var out [admission.PredictionSlots]uint64
	if m.base.IsZero() {
		return out
	}
	now := m.minute(mono)
	for _, b := range m.buckets {
		if !b.set || b.minute > now || b.minute <= now-int64(len(m.buckets)) {
			continue
		}
		for p, n := range b.counts {
			out[p] += min(n, ^uint64(0)-out[p])
		}
	}
	return out
}
