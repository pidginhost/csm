package responsereplay

import (
	"errors"
	"math/rand"
	"net"
	"slices"
	"strings"
	"time"
)

// Classifier supplies the decisions the live path takes from policy code this
// package cannot import. The replay command and the cross-check tests build
// it from the real registry wrappers.
type Classifier struct {
	// Blockable reports whether a finding may drive a single-IP scan block.
	Blockable func(Finding) bool
	// ChallengeFirst reports whether the live path routes the finding to the
	// challenge instead of blocking it.
	ChallengeFirst func(Finding) bool
	// SourceIP extracts the address the live path would block, or "".
	SourceIP func(Finding) string
	// ExemptBlock recognises a recorded block from a path outside the scan
	// budget (challenge timeout, central intel, credential spray, incident).
	ExemptBlock func(Finding) (ObservedBlock, bool)
}

// ObservedBlock is a recorded block the model applies as given.
type ObservedBlock struct {
	IP  string
	TTL time.Duration
}

// LegacyConfig is the resolved configuration of the scan admission path.
// Callers resolve defaults first; a zero cap is invalid here, never
// "exhausted".
type LegacyConfig struct {
	MaxPerHour    int
	DenyTempLimit int // 0 means unlimited
	BlockTTL      time.Duration
	PendingBound  int
	PendingMaxAge time.Duration
	// HourLocation is the zone the live clock formats the hour key in.
	HourLocation *time.Location
	Seed         int64
}

// PendingEntry is a queued candidate. QueuedAt is zero until first queued.
type PendingEntry struct {
	Finding  Finding
	IP       string
	QueuedAt time.Time
}

// TempEntry is one blocked address in firewall insertion order. A zero
// ExpiresAt is a permanent block, which never counts against the temporary
// limit and is never evicted.
type TempEntry struct {
	IP        string
	BlockedAt time.Time
	ExpiresAt time.Time
}

// LegacyState is the model's whole state, as the live path persists it.
type LegacyState struct {
	HourKey        string
	BlocksThisHour int
	Pending        []PendingEntry
	Entries        []TempEntry
}

// BatchOutcome is what one step did. Blocked counts new scan blocks,
// ExemptBlocked new blocks from observed exempt paths. Requeued is the
// pending length after the step, not a sum. For every step
//
//	prior pending + NewCandidates =
//	    Blocked + Requeued + AgedOut + Overflowed +
//	    InvalidPending + IneligiblePending + PendingSatisfied
type BatchOutcome struct {
	Blocked, Requeued, AgedOut, Overflowed, Evicted, ExemptBlocked int
	// ExemptObserved counts recorded exempt rows, including ones that found
	// the address already blocked and changed nothing.
	ExemptObserved int
	// Eligible counts blockable rows. MissingIP, AlreadyBlocked and
	// ChallengeSkipped are eligible rows that produced no candidate.
	Eligible, MissingIP, ChallengeSkipped, AlreadyBlocked int
	// NewCandidates counts new addresses after deduplication against the
	// step and the queue. FirstQueued counts candidates queued for the
	// first time; neither counts a requeue.
	NewCandidates, FirstQueued                          int
	InvalidPending, IneligiblePending, PendingSatisfied int
	// BlockedIPs and EvictedIPs are for tests and internal accounting only;
	// reports carry counts.
	BlockedIPs, EvictedIPs []string
	// QueueDelays holds, for each queued candidate that got blocked, the
	// time from first queueing to the block. EvictionResidences holds, for
	// each eviction, how long the victim had been blocked.
	QueueDelays, EvictionResidences []time.Duration
	PendingHighWater, LiveHighWater int
}

// Legacy models the live scan admission path: the hourly counter, the
// bounded pending queue with its age limit, the random order candidates are
// tried in, and the temporary deny limit's eviction. It is not the
// production code and makes no decision for it.
type Legacy struct {
	cfg     LegacyConfig
	classes Classifier
	state   LegacyState
	rng     *rand.Rand
	now     time.Time
}

var (
	errLegacyConfig  = errors.New("replay: invalid legacy configuration")
	errLegacyState   = errors.New("replay: invalid initial state")
	errTimeBackwards = errors.New("replay: batch earlier than the previous one")
)

// NewLegacy validates the configuration and copies the initial state.
func NewLegacy(cfg LegacyConfig, classes Classifier, initial LegacyState) (*Legacy, error) {
	if cfg.MaxPerHour <= 0 || cfg.DenyTempLimit < 0 || cfg.BlockTTL <= 0 || cfg.PendingBound <= 0 ||
		cfg.PendingMaxAge <= 0 || cfg.HourLocation == nil || classes.Blockable == nil ||
		classes.ChallengeFirst == nil || classes.SourceIP == nil || classes.ExemptBlock == nil {
		return nil, errLegacyConfig
	}
	// The live queue holds one entry per address and the live set one block
	// per address; a state that breaks either cannot come from it.
	queued := map[string]bool{}
	for _, p := range initial.Pending {
		key := normalizeIP(p.IP)
		if key == "" {
			key = p.IP
		}
		if queued[key] {
			return nil, errLegacyState
		}
		queued[key] = true
	}
	for i, e := range initial.Entries {
		if _, ok := canonicalKey(e.IP); !ok {
			return nil, errLegacyState
		}
		for _, other := range initial.Entries[:i] {
			if sameAddr(e.IP, other.IP) {
				return nil, errLegacyState
			}
		}
	}
	return &Legacy{cfg: cfg, classes: classes, state: copyState(initial), rng: rand.New(rand.NewSource(cfg.Seed))}, nil // #nosec G404 -- reproducible replay order, not security
}

// Snapshot returns a deep copy of the current state.
func (l *Legacy) Snapshot() LegacyState { return copyState(l.state) }

func copyState(s LegacyState) LegacyState {
	s.Pending = slices.Clone(s.Pending)
	s.Entries = slices.Clone(s.Entries)
	return s
}

// Blocked reports whether ip holds a block at now.
func (l *Legacy) Blocked(ip string, now time.Time) bool {
	for _, e := range l.state.Entries {
		if sameAddr(e.IP, ip) && (e.ExpiresAt.IsZero() || now.Before(e.ExpiresAt)) {
			return true
		}
	}
	return false
}

// Step applies one batch at batch.At.
func (l *Legacy) Step(batch Batch) (BatchOutcome, error) {
	if batch.At.Before(l.now) {
		return BatchOutcome{}, errTimeBackwards
	}
	now := batch.At
	l.now = now
	var out BatchOutcome
	l.state.Entries = slices.DeleteFunc(l.state.Entries, func(e TempEntry) bool {
		return !e.ExpiresAt.IsZero() && !e.ExpiresAt.After(now)
	})
	out.LiveHighWater = len(l.state.Entries)
	if key := now.In(l.cfg.HourLocation).Format("2006-01-02T15"); key != l.state.HourKey {
		l.state.HourKey = key
		l.state.BlocksThisHour = 0
	}

	// Recorded exempt blocks are applied as given, before the scan stage:
	// their order against a scan at the same instant is not recorded.
	for _, f := range batch.Findings {
		obs, ok := l.classes.ExemptBlock(f)
		if !ok {
			continue
		}
		out.ExemptObserved++
		ip := normalizeIP(obs.IP)
		if ip == "" || obs.TTL <= 0 || l.Blocked(ip, now) {
			continue
		}
		l.insert(&out, ip, now, obs.TTL)
		out.ExemptBlocked++
	}

	candidates := map[string]PendingEntry{}
	for _, p := range l.state.Pending {
		// The stored address is what the live drain checks; the message is
		// not re-read.
		ip := normalizeIP(p.IP)
		switch {
		case ip == "":
			out.InvalidPending++
		case !l.classes.Blockable(p.Finding):
			out.IneligiblePending++
		case !p.QueuedAt.IsZero() && now.Sub(p.QueuedAt) > l.cfg.PendingMaxAge:
			out.AgedOut++
		case l.Blocked(ip, now):
			out.PendingSatisfied++
		default:
			p.IP = ip
			candidates[ip] = p
		}
	}
	l.state.Pending = nil

	for _, f := range batch.Findings {
		if !l.classes.Blockable(f) {
			continue
		}
		out.Eligible++
		ip := l.classes.SourceIP(f)
		switch {
		case ip == "":
			out.MissingIP++
			continue
		case l.Blocked(ip, now):
			out.AlreadyBlocked++
			continue
		case l.classes.ChallengeFirst(f):
			out.ChallengeSkipped++
			continue
		}
		// A repeat refreshes the evidence and keeps the queue time.
		if existing, ok := candidates[ip]; ok {
			existing.Finding = f
			candidates[ip] = existing
			continue
		}
		candidates[ip] = PendingEntry{Finding: f, IP: ip}
		out.NewCandidates++
	}

	// The live path ranges over a Go map. Sorting the keys and shuffling
	// them with the seeded generator gives a reproducible random order, not
	// Go's own order or distribution.
	order := make([]string, 0, len(candidates))
	for ip := range candidates {
		order = append(order, ip)
	}
	slices.Sort(order)
	l.rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	for _, ip := range order {
		c := candidates[ip]
		if l.state.BlocksThisHour >= l.cfg.MaxPerHour {
			if c.QueuedAt.IsZero() {
				c.QueuedAt = now
				if len(l.state.Pending) < l.cfg.PendingBound {
					out.FirstQueued++
				}
			}
			if len(l.state.Pending) < l.cfg.PendingBound {
				l.state.Pending = append(l.state.Pending, c)
				out.PendingHighWater = max(out.PendingHighWater, len(l.state.Pending))
			} else {
				out.Overflowed++
			}
			continue
		}
		l.insert(&out, ip, now, l.cfg.BlockTTL)
		l.state.BlocksThisHour++
		out.Blocked++
		out.BlockedIPs = append(out.BlockedIPs, ip)
		if !c.QueuedAt.IsZero() {
			out.QueueDelays = append(out.QueueDelays, now.Sub(c.QueuedAt))
		}
	}
	out.Requeued = len(l.state.Pending)
	return out, nil
}

// insert adds a temporary block, first evicting the soonest-expiring
// temporary entry when the limit is full, as the engine does.
func (l *Legacy) insert(out *BatchOutcome, ip string, now time.Time, ttl time.Duration) {
	if l.cfg.DenyTempLimit > 0 && l.temporaryCount() >= l.cfg.DenyTempLimit {
		if victim, ok := evictionVictim(l.state.Entries, ip); ok {
			i := slices.IndexFunc(l.state.Entries, func(e TempEntry) bool { return e.IP == victim })
			out.Evicted++
			out.EvictedIPs = append(out.EvictedIPs, victim)
			out.EvictionResidences = append(out.EvictionResidences, now.Sub(l.state.Entries[i].BlockedAt))
			l.state.Entries = slices.Delete(l.state.Entries, i, i+1)
		}
	}
	l.state.Entries = append(l.state.Entries, TempEntry{IP: ip, BlockedAt: now, ExpiresAt: now.Add(ttl)})
	out.LiveHighWater = max(out.LiveHighWater, len(l.state.Entries))
}

func (l *Legacy) temporaryCount() int {
	n := 0
	for _, e := range l.state.Entries {
		if !e.ExpiresAt.IsZero() {
			n++
		}
	}
	return n
}

// evictionVictim is the engine's rule: the first entry with the earliest
// expiry, skipping permanent entries and the address being blocked. It does
// not skip expired entries; the caller prunes those first.
func evictionVictim(entries []TempEntry, exclude string) (string, bool) {
	var best TempEntry
	found := false
	for _, e := range entries {
		if e.ExpiresAt.IsZero() || sameAddr(e.IP, exclude) {
			continue
		}
		if !found || e.ExpiresAt.Before(best.ExpiresAt) {
			best, found = e, true
		}
	}
	return best.IP, found
}

// normalizeIP is the live queue's address rule, step for step: surrounding
// space, a port and brackets are stripped, loopback and unspecified
// addresses are refused, and the result is the canonical text form.
func normalizeIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	ip := net.ParseIP(strings.Trim(raw, "[]"))
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

// canonicalKey and sameAddr compare addresses exactly as the firewall
// does: by net.ParseIP's canonical text, so an IPv4-mapped IPv6 address is
// its IPv4 address and two spellings of one IPv6 address are equal.
func canonicalKey(s string) (string, bool) {
	ip := net.ParseIP(s)
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

func sameAddr(a, b string) bool {
	if a == b {
		return true
	}
	x, ok := canonicalKey(a)
	if !ok {
		return false
	}
	y, ok := canonicalKey(b)
	return ok && x == y
}
