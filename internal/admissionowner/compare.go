package admissionowner

import (
	"sort"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/checks"
)

// Decisions the comparison counts. A preview is the decision a live
// attempt would have been executed on.
const (
	decisionRefused   = "refused"
	decisionQueued    = "queued"
	decisionCoalesced = "coalesced"
	decisionObserve   = "observe"
)

// maxUnwrittenRows bounds history while the action log cannot be written.
const maxUnwrittenRows = 4096

type compareKey struct {
	entry    admission.Entry
	check    string
	kind     admission.Kind
	decision string
	reason   admission.Reason
}

// Funnels count without waiting on the owner. The fixed check vocabulary
// keeps malformed findings and absent derived roots from growing the map.
type comparison struct {
	mu        sync.Mutex
	start     time.Time
	counts    map[compareKey]uint64
	next      uint64
	unwritten []comparisonRow
}

type comparisonRow struct {
	actionlog.Record
	sequence uint64
}

func (c *comparison) add(k compareKey) { c.addAt(k, deliveryNow()) }

func (c *comparison) addAt(k compareKey, now time.Time) { c.addCountAt(k, 1, now) }

func (c *comparison) addCountAt(k compareKey, n uint64, now time.Time) {
	if n == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, registered := checks.LookupCheck(k.check); !registered {
		k.check = "unknown"
	}
	hour := now.UTC().Truncate(time.Hour)
	if c.start.IsZero() {
		c.start = hour
	} else if hour.After(c.start) {
		c.closeHour()
		c.start = hour
	}
	if c.counts == nil {
		c.counts = map[compareKey]uint64{}
	}
	c.counts[k] += n
}

// begin advances the hour floor after a committed admission clock reading,
// including readings made by a startup that later fails.
func (c *comparison) begin(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.start.IsZero() {
		c.start = now.UTC().Truncate(time.Hour)
	} else if hour := now.UTC().Truncate(time.Hour); hour.After(c.start) {
		c.closeHour()
		c.start = hour
	}
}

// closeHour requires mu. Retention sorts before trimming, so a backdated
// batch can never evict newer evidence merely by append order.
func (c *comparison) closeHour() {
	end := c.start.Add(time.Hour)
	for k, n := range c.counts {
		r := actionlog.Record{
			Timestamp: end, Op: "respond.block_ip", Action: k.kind.String(), Actor: actionlog.Daemon,
			ActorDetail: k.entry.String(), Reason: k.check, Result: actionlog.Result(k.decision), Count: n,
		}
		if k.reason != 0 {
			r.Error = k.reason.String()
		}
		c.next++
		c.unwritten = append(c.unwritten, comparisonRow{Record: r, sequence: c.next})
	}
	c.counts = nil
	sort.SliceStable(c.unwritten, func(i, j int) bool { return c.unwritten[i].Timestamp.Before(c.unwritten[j].Timestamp) })
	if extra := len(c.unwritten) - maxUnwrittenRows; extra > 0 {
		cut := extra
		for cut < len(c.unwritten) && c.unwritten[cut].Timestamp.Equal(c.unwritten[cut-1].Timestamp) {
			cut++
		}
		copy(c.unwritten, c.unwritten[cut:])
		c.unwritten = c.unwritten[:len(c.unwritten)-cut]
	}
}

// take returns the rows still to write and the sequence they end at: those
// of earlier failed writes and, once its hour has ended by now, or at once
// when final is set, the current hour's, stamped with that hour's end.
func (c *comparison) take(now time.Time, final bool) ([]actionlog.Record, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.start.IsZero() && (final || !now.Before(c.start.Add(time.Hour))) {
		c.closeHour()
		if hour := now.UTC().Truncate(time.Hour); hour.After(c.start) {
			c.start = hour
		}
	}
	rows := make([]actionlog.Record, len(c.unwritten))
	for i, r := range c.unwritten {
		rows[i] = r.Record
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Timestamp.Before(rows[j].Timestamp) })
	return rows, c.next
}

// A writer acknowledges the immutable batch it took. Funnels can close
// newer hours while that write blocks, and retention can retire old rows.
func (c *comparison) written(through uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := c.unwritten[:0]
	for _, r := range c.unwritten {
		if r.sequence > through {
			kept = append(kept, r)
		}
	}
	c.unwritten = kept
}
