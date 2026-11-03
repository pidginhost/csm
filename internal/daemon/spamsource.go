package daemon

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

const (
	spamSourceOccasions   = 2
	spamSourceOccasionGap = time.Hour
	spamSourceWindow      = 7 * 24 * time.Hour
	spamSourceCleanWindow = 30 * 24 * time.Hour
	spamSourceThrottle    = 24 * time.Hour
	spamSourceMaxIPs      = 50_000
	// spamSourceRejectReserve is the percent of the bound that IPs with
	// recent clean mail cannot take from IPs without it.
	spamSourceRejectReserve = 10
)

type spamSourceEntry struct {
	store.SpamSource
}

// spamSourceTracker holds per-IP spam scan history for at most max IPs. To
// make room for a new IP it drops one without recent clean mail first, but
// keeps a reserve of the bound for those IPs.
type spamSourceTracker struct {
	mu      sync.Mutex
	max     int
	entries map[netip.Addr]*spamSourceEntry
	// Pending checks retain their entry identity across eviction. They are
	// never saved: a restart cannot finish work from the previous process.
	checking map[netip.Addr]*spamSourceEntry
}

func newSpamSourceTracker(max int) *spamSourceTracker {
	return &spamSourceTracker{
		max: max, entries: make(map[netip.Addr]*spamSourceEntry),
		checking: make(map[netip.Addr]*spamSourceEntry),
	}
}

// observe records one scan. It returns true when ip qualifies, is not
// throttled and has no check in flight, and marks the check in flight.
func (t *spamSourceTracker) observe(ip netip.Addr, reject, clean bool, at time.Time) bool {
	if !reject && !clean {
		return false
	}
	ip = ip.Unmap()
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[ip]
	if e == nil {
		if len(t.entries) >= t.max {
			t.evict(at)
		}
		e = &spamSourceEntry{}
		t.entries[ip] = e
	}
	if at.After(e.Seen) {
		e.Seen = at
	}
	if clean && at.After(e.LastClean) {
		e.LastClean = at
	}
	if !reject {
		return false
	}
	// One message split into several deliveries, or a re-read log line, lands
	// inside the occasion it belongs to and is counted once.
	if n := len(e.Occasions); n == 0 || !at.Before(e.Occasions[n-1].Add(spamSourceOccasionGap)) {
		e.Occasions = append(e.Occasions, at)
	}
	cut := at.Add(-spamSourceWindow)
	e.Occasions = slices.DeleteFunc(e.Occasions, func(o time.Time) bool { return o.Before(cut) })
	if n := len(e.Occasions); n > spamSourceOccasions {
		e.Occasions = e.Occasions[n-spamSourceOccasions:]
	}
	if t.checking[ip] != nil || !e.qualifies(at) {
		return false
	}
	t.checking[ip] = e
	return true
}

// forget drops ip's history. A check in flight for it then ends unreported,
// because finish finds no entry.
func (t *spamSourceTracker) forget(ip netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, ip.Unmap())
}

// finish ends the check in flight. If ip still qualifies, emit runs under
// the lock; when it returns true the throttle starts at at.
func (t *spamSourceTracker) finish(ip netip.Addr, at time.Time, emit func() bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	ip = ip.Unmap()
	e := t.checking[ip]
	delete(t.checking, ip)
	// A completion belongs to the entry it checked, never a replacement
	// inserted for the same address after eviction.
	if e == nil || t.entries[ip] != e {
		return false
	}
	// Clean mail that arrived during the check cancels the finding here.
	if !e.qualifies(at) || !emit() {
		return false
	}
	e.LastFinding = at
	return true
}

// qualifies treats zero times as long past, so an IP with no clean mail or no
// finding yet passes those two tests.
func (e *spamSourceEntry) qualifies(at time.Time) bool {
	from := at.Add(-spamSourceWindow)
	n := 0
	for _, o := range e.Occasions {
		if !o.Before(from) && !o.After(at) {
			n++
		}
	}
	return n >= spamSourceOccasions &&
		e.LastClean.Before(at.Add(-spamSourceCleanWindow)) &&
		!e.LastFinding.After(at.Add(-spamSourceThrottle))
}

// evict makes room for one IP. Recent clean mail is what keeps a mostly good
// sender from being reported, so the least recently seen IP without clean mail
// in the clean window before now goes first. Clean IPs still may not fill the
// reserve: past their share the least recently seen clean IP goes, as it does
// when no other IP is left.
//
// One pass under the lock counts the clean IPs exactly and tracks the least
// recently seen IP of each class. It runs only when a new IP arrives with the
// tracker full, so it costs a scan of the bound per such insert and nothing on
// the per-message path otherwise. A cached count would drift as clean mail ages
// out. Move to one LRU list per class if profiles show this scan; entries would
// then change lists, and the count would change, as their clean mail ages out.
func (t *spamSourceTracker) evict(now time.Time) {
	cut := now.Add(-spamSourceCleanWindow)
	var oldestClean, oldestOther netip.Addr
	var cleanSeen, otherSeen time.Time
	clean, other := 0, 0
	for ip, e := range t.entries {
		if !e.LastClean.Before(cut) {
			if clean == 0 || e.Seen.Before(cleanSeen) {
				oldestClean, cleanSeen = ip, e.Seen
			}
			clean++
		} else {
			if other == 0 || e.Seen.Before(otherSeen) {
				oldestOther, otherSeen = ip, e.Seen
			}
			other++
		}
	}
	// Over the share means clean > max*(100-reserve)/100, kept in integers
	// as clean*100 > max*(100-reserve) so it is exact for every bound.
	if other == 0 || clean*100 > t.max*(100-spamSourceRejectReserve) {
		delete(t.entries, oldestClean)
		return
	}
	delete(t.entries, oldestOther)
}

func (t *spamSourceTracker) snapshot() map[string]store.SpamSource {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]store.SpamSource, len(t.entries))
	for ip, e := range t.entries {
		src := e.SpamSource
		src.Occasions = slices.Clone(src.Occasions)
		out[ip.String()] = src
	}
	return out
}

// load replaces the tracker state with m. An IP unseen for the clean window
// carries nothing that can still block or count toward a finding, so it is
// dropped along with keys that are not IPs.
func (t *spamSourceTracker) load(m map[string]store.SpamSource, now time.Time) {
	cut := now.Add(-spamSourceCleanWindow)
	entries := make(map[netip.Addr]*spamSourceEntry, len(m))
	for key, src := range m {
		ip, err := netip.ParseAddr(key)
		if err != nil || src.Seen.Before(cut) {
			continue
		}
		src.Occasions = slices.Clone(src.Occasions)
		entries[ip.Unmap()] = &spamSourceEntry{SpamSource: src}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = entries
	clear(t.checking)
	t.trimLoaded(now)
}

// trimLoaded applies the same eviction policy to oversized saved state.
// Sort once rather than rescanning the whole map for each excess entry.
func (t *spamSourceTracker) trimLoaded(now time.Time) {
	if len(t.entries) <= t.max {
		return
	}
	cut := now.Add(-spamSourceCleanWindow)
	var clean, other []netip.Addr
	for ip, e := range t.entries {
		if !e.LastClean.Before(cut) {
			clean = append(clean, ip)
		} else {
			other = append(other, ip)
		}
	}
	oldest := func(a, b netip.Addr) int {
		if order := t.entries[a].Seen.Compare(t.entries[b].Seen); order != 0 {
			return order
		}
		return a.Compare(b)
	}
	slices.SortFunc(clean, oldest)
	slices.SortFunc(other, oldest)
	for len(t.entries) > t.max {
		if len(other) == 0 || len(clean)*100 > t.max*(100-spamSourceRejectReserve) {
			delete(t.entries, clean[0])
			clean = clean[1:]
		} else {
			delete(t.entries, other[0])
			other = other[1:]
		}
	}
}
