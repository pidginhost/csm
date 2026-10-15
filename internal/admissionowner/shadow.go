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
)

func (r resetReason) String() string {
	switch r {
	case resetStartup:
		return "startup"
	case resetModeChange:
		return "mode_change"
	}
	return ""
}

// newSessionID reads a random 128-bit forecast session ID.
func newSessionID(r io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// shadowEntry is one forecast block: its kind and absolute lease expiry.
type shadowEntry struct {
	kind    admission.Kind
	expires time.Time
}

// shadowChange is a capacity admission a forecast decided and has not
// installed: one charge and one entry.
type shadowChange struct {
	ip     string
	entry  shadowEntry
	charge admission.Charge
	next   admission.CeilingState
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

// expire drops the forecast blocks whose lease has ended at lease, a
// reading of the engine's lease clock.
func (s *shadow) expire(lease time.Time) {
	for ip, e := range s.entries {
		if !lease.Before(e.expires) {
			delete(s.entries, ip)
		}
	}
}

// ips are the forecast addresses, in order, for an admission snapshot to
// count the real blocks of.
func (s *shadow) ips() []string { return slices.Sorted(maps.Keys(s.entries)) }

// covering says how a forecast block holds ip for a pick lasting until
// expires: one that lasts at least as long answers it, a shorter one holds
// the address as live work would wait for it. Zero when none holds it.
func (s *shadow) covering(ip string, expires time.Time) admission.Prediction {
	e, ok := s.entries[ip]
	switch {
	case !ok:
		return 0
	case e.expires.Before(expires):
		return admission.PredictPendingRecovery
	}
	return admission.PredictExistingShadow
}

// occupancy is the predicted temporary occupancy: the real one, plus the
// forecast blocks, less those the real sets already hold as a timed or an
// untimed element. adm is this turn's snapshot, taken after expire.
func (s *shadow) occupancy(adm firewall.BlockAdmission) int {
	return adm.Temporary + len(s.entries) - adm.ShadowTemporary - adm.ShadowPermanent
}

// full reports whether real and forecast blocks fill the temporary limit.
// A zero limit is the base engine's unlimited set.
func (s *shadow) full(adm firewall.BlockAdmission) bool {
	return adm.Limit > 0 && s.occupancy(adm) >= adm.Limit
}

// limited reports whether the forecast can model no other active block.
func (s *shadow) limited() bool { return len(s.entries) >= forecastEntries }

// admit decides a ready pick of kind for ip lasting until expires, at
// admission time now, against this turn's snapshot: a full set first, then
// the modelling bound, then the ceiling on each of lanes in order, the
// selected lane first. Only a capacity admission returns a change; nothing
// is installed until commit. Kinds outside the address model take no capacity.
func (s *shadow) admit(ip string, kind admission.Kind, expires time.Time, lanes []admission.Lane, now time.Time, adm firewall.BlockAdmission) (admission.Prediction, *shadowChange, error) {
	switch {
	case kind != admission.KindBlockIP:
		return admission.PredictNotModelled, nil, nil
	case s.full(adm):
		return admission.PredictSetFull, nil, nil
	case s.limited():
		return admission.PredictForecastLimited, nil, nil
	}
	cost := kind.CeilingCost()
	for _, lane := range lanes {
		next, err := s.ceiling.Charge(lane, cost)
		if reason, refused := admission.ReasonOf(err); refused && reason == admission.ReasonCeiling {
			continue
		}
		if err != nil {
			return 0, nil, err
		}
		return admission.PredictCapacityAdmit, &shadowChange{
			ip: ip, entry: shadowEntry{kind: kind, expires: expires}, next: next,
			charge: admission.Charge{At: now, Lane: lane, Cost: cost, Elapsed: s.ceiling.Elapsed},
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
