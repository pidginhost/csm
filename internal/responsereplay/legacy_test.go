package responsereplay

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

// testClassifier stands in for the registry wrappers: "hard" blocks,
// "soft" routes to the challenge, "critical_only" blocks only at Critical,
// "exempt" is an observed block from outside the scan budget. The address
// follows the last " from ".
func testClassifier() Classifier {
	return Classifier{
		Blockable: func(f Finding) bool {
			return f.Check == "hard" || f.Check == "soft" || (f.Check == "critical_only" && f.Severity == "CRITICAL")
		},
		ChallengeFirst: func(f Finding) bool { return f.Check == "soft" },
		SourceIP: func(f Finding) string {
			i := strings.LastIndex(f.Message, " from ")
			if i < 0 {
				return ""
			}
			return normalizeIP(f.Message[i+len(" from "):])
		},
		ExemptBlock: func(f Finding) (ObservedBlock, bool) {
			if f.Check != "exempt" {
				return ObservedBlock{}, false
			}
			ip, ttl, _ := strings.Cut(f.Details, " ")
			d, err := time.ParseDuration(ttl)
			return ObservedBlock{IP: ip, TTL: d}, err == nil
		},
	}
}

func testConfig(capacity int) LegacyConfig {
	return LegacyConfig{MaxPerHour: capacity, BlockTTL: time.Hour, PendingBound: 1000, PendingMaxAge: 2 * time.Hour, HourLocation: time.UTC, Seed: 1}
}

func hard(ip string) Finding {
	return Finding{Check: "hard", Severity: "CRITICAL", Message: "attack from " + ip}
}

func ips(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d", prefix, i+1)
	}
	return out
}

func hardBatch(at time.Time, addrs ...string) Batch {
	b := Batch{At: at}
	for _, a := range addrs {
		b.Findings = append(b.Findings, hard(a))
	}
	return b
}

func newTestLegacy(t *testing.T, cfg LegacyConfig, initial LegacyState) *Legacy {
	t.Helper()
	l, err := NewLegacy(cfg, testClassifier(), initial)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// step runs one batch and checks the conservation law every step obeys.
func step(t *testing.T, l *Legacy, b Batch) BatchOutcome {
	t.Helper()
	prior := len(l.Snapshot().Pending)
	out, err := l.Step(b)
	if err != nil {
		t.Fatal(err)
	}
	if lhs, rhs := prior+out.NewCandidates, out.Blocked+out.Requeued+out.AgedOut+out.Overflowed+out.InvalidPending+out.IneligiblePending+out.PendingSatisfied; lhs != rhs {
		t.Fatalf("population not conserved: %d in, %d out (%+v)", lhs, rhs, out)
	}
	if out.Blocked != len(out.BlockedIPs) || out.Evicted != len(out.EvictedIPs) || out.Evicted != len(out.EvictionResidences) {
		t.Fatalf("counts disagree with their lists: %+v", out)
	}
	return out
}

func TestLegacyUnderCapBlocksEveryCandidate(t *testing.T) {
	l := newTestLegacy(t, testConfig(10), LegacyState{})
	out := step(t, l, hardBatch(t0, ips("203.0.113.", 3)...))
	if out.Blocked != 3 || out.Requeued != 0 || out.NewCandidates != 3 || out.Eligible != 3 {
		t.Fatalf("%+v", out)
	}
	if s := l.Snapshot(); s.BlocksThisHour != 3 || s.HourKey != "2026-09-08T12" || len(s.Entries) != 3 {
		t.Fatalf("state: %+v", s)
	}
}

func TestLegacyOverCapQueuesThenDrainsNextHour(t *testing.T) {
	l := newTestLegacy(t, testConfig(10), LegacyState{})
	addrs := ips("203.0.113.", 12)
	out := step(t, l, hardBatch(t0, addrs...))
	if out.Blocked != 10 || out.Requeued != 2 || out.FirstQueued != 2 || out.PendingHighWater != 2 {
		t.Fatalf("over cap: %+v", out)
	}
	queued := l.Snapshot().Pending
	for _, p := range queued {
		if !p.QueuedAt.Equal(t0) || slices.Contains(out.BlockedIPs, p.IP) || !slices.Contains(addrs, p.IP) {
			t.Fatalf("queued entry %+v", p)
		}
	}
	next := step(t, l, Batch{At: t0.Add(time.Hour)})
	if next.Blocked != 2 || next.Requeued != 0 || next.FirstQueued != 0 || next.NewCandidates != 0 {
		t.Fatalf("next hour: %+v", next)
	}
	if !reflect.DeepEqual(next.QueueDelays, []time.Duration{time.Hour, time.Hour}) {
		t.Fatalf("queue delays = %v", next.QueueDelays)
	}
	if s := l.Snapshot(); s.BlocksThisHour != 2 || s.HourKey != "2026-09-08T13" {
		t.Fatalf("counter not reset: %+v", s)
	}
}

func TestLegacyDeduplicatesAddressesWithinABatch(t *testing.T) {
	l := newTestLegacy(t, testConfig(10), LegacyState{})
	out := step(t, l, hardBatch(t0, "203.0.113.1", "203.0.113.1", "::ffff:203.0.113.1"))
	if out.Blocked != 1 || out.NewCandidates != 1 || out.Eligible != 3 {
		t.Fatalf("%+v", out)
	}
}

func spentCap(capacity int, pending ...PendingEntry) LegacyState {
	return LegacyState{HourKey: t0.Format("2006-01-02T15"), BlocksThisHour: capacity, Pending: pending}
}

func TestLegacyRequeueKeepsFirstQueueTime(t *testing.T) {
	queuedAt := t0.Add(-30 * time.Minute)
	l := newTestLegacy(t, testConfig(10), spentCap(10, PendingEntry{Finding: hard("203.0.113.5"), IP: "203.0.113.5", QueuedAt: queuedAt}))
	refreshed := Finding{Check: "critical_only", Severity: "CRITICAL", Message: "new evidence from 203.0.113.5", FindingID: "fid-new"}
	out := step(t, l, Batch{At: t0, Findings: []Finding{refreshed}})
	pending := l.Snapshot().Pending
	if out.NewCandidates != 0 || out.FirstQueued != 0 || len(pending) != 1 || !pending[0].QueuedAt.Equal(queuedAt) || pending[0].Finding != refreshed {
		t.Fatalf("requeue lost its queue time or kept stale evidence: %+v %+v", out, pending)
	}
}

func TestLegacyAgeBoundaryIsStrict(t *testing.T) {
	queued := PendingEntry{Finding: hard("203.0.113.5"), IP: "203.0.113.5", QueuedAt: t0}
	l := newTestLegacy(t, testConfig(10), LegacyState{HourKey: t0.Add(2 * time.Hour).Format("2006-01-02T15"), BlocksThisHour: 10, Pending: []PendingEntry{queued}})
	out := step(t, l, Batch{At: t0.Add(2 * time.Hour)})
	if out.AgedOut != 0 || out.Requeued != 1 || !l.Snapshot().Pending[0].QueuedAt.Equal(t0) {
		t.Fatalf("entry aged out at exactly the limit: %+v", out)
	}
	out = step(t, l, Batch{At: t0.Add(2*time.Hour + time.Nanosecond)})
	if out.AgedOut != 1 || out.Requeued != 0 || out.Blocked != 0 {
		t.Fatalf("entry survived past the limit: %+v", out)
	}
}

func TestLegacyQueueBoundCountsOverflow(t *testing.T) {
	cfg := testConfig(1)
	cfg.PendingBound = 3
	l := newTestLegacy(t, cfg, spentCap(1))
	out := step(t, l, hardBatch(t0, ips("203.0.113.", 5)...))
	if out.Blocked != 0 || out.Requeued != 3 || out.Overflowed != 2 || out.FirstQueued != 3 || out.NewCandidates != 5 {
		t.Fatalf("%+v", out)
	}
}

func TestLegacyRequeueStampsOnlyUnqueuedCandidates(t *testing.T) {
	earlier := t0.Add(-time.Hour)
	l := newTestLegacy(t, testConfig(1), spentCap(1, PendingEntry{Finding: hard("203.0.113.1"), IP: "203.0.113.1", QueuedAt: earlier}))
	step(t, l, hardBatch(t0, "203.0.113.2"))
	got := map[string]time.Time{}
	for _, p := range l.Snapshot().Pending {
		got[p.IP] = p.QueuedAt
	}
	if !got["203.0.113.1"].Equal(earlier) || !got["203.0.113.2"].Equal(t0) {
		t.Fatalf("queue times: %v", got)
	}
}

func TestLegacyDrainRevalidatesStoredEvidence(t *testing.T) {
	l := newTestLegacy(t, testConfig(10), LegacyState{Pending: []PendingEntry{
		{Finding: Finding{Check: "critical_only", Severity: "HIGH"}, IP: "203.0.113.1", QueuedAt: t0},
		{Finding: hard("x"), IP: "not-an-address", QueuedAt: t0},
		{Finding: hard("x"), IP: "127.0.0.1", QueuedAt: t0},
		// The stored address is used, not the message.
		{Finding: hard("198.51.100.99"), IP: "203.0.113.3", QueuedAt: t0},
	}})
	out := step(t, l, Batch{At: t0})
	if out.IneligiblePending != 1 || out.InvalidPending != 2 || !reflect.DeepEqual(out.BlockedIPs, []string{"203.0.113.3"}) {
		t.Fatalf("%+v", out)
	}
}

// The live drain does not re-apply challenge routing to queued work: an
// entry queued while it was a block stays a block.
func TestLegacyDrainDoesNotReapplyChallengeRouting(t *testing.T) {
	queued := PendingEntry{Finding: Finding{Check: "soft", Severity: "HIGH", Message: "x from 203.0.113.1"}, IP: "203.0.113.1", QueuedAt: t0}
	l := newTestLegacy(t, testConfig(10), LegacyState{Pending: []PendingEntry{queued}})
	fresh := Finding{Check: "soft", Severity: "HIGH", Message: "x from 203.0.113.2"}
	out := step(t, l, Batch{At: t0, Findings: []Finding{fresh}})
	if !reflect.DeepEqual(out.BlockedIPs, []string{"203.0.113.1"}) || out.ChallengeSkipped != 1 {
		t.Fatalf("%+v", out)
	}
}

func TestLegacyFreshEvidenceAfterAgeOutIsANewCandidate(t *testing.T) {
	l := newTestLegacy(t, testConfig(1), LegacyState{HourKey: t0.Add(3 * time.Hour).Format("2006-01-02T15"), BlocksThisHour: 1,
		Pending: []PendingEntry{{Finding: hard("203.0.113.1"), IP: "203.0.113.1", QueuedAt: t0}}})
	out := step(t, l, hardBatch(t0.Add(3*time.Hour), "203.0.113.1"))
	pending := l.Snapshot().Pending
	if out.AgedOut != 1 || out.NewCandidates != 1 || out.FirstQueued != 1 || len(pending) != 1 || !pending[0].QueuedAt.Equal(t0.Add(3*time.Hour)) {
		t.Fatalf("%+v %+v", out, pending)
	}
}

func TestLegacyBlockExpiresExactlyAtTTL(t *testing.T) {
	l := newTestLegacy(t, testConfig(10), LegacyState{})
	step(t, l, hardBatch(t0, "203.0.113.1"))
	for at, want := range map[time.Duration]bool{0: true, time.Hour - time.Nanosecond: true, time.Hour: false, time.Hour + time.Nanosecond: false} {
		if got := l.Blocked("203.0.113.1", t0.Add(at)); got != want {
			t.Errorf("Blocked at +%v = %v", at, got)
		}
	}
	if out := step(t, l, hardBatch(t0.Add(time.Hour-time.Nanosecond), "203.0.113.1")); out.Blocked != 0 || out.AlreadyBlocked != 1 {
		t.Fatalf("re-blocked before expiry: %+v", out)
	}
	if out := step(t, l, hardBatch(t0.Add(time.Hour), "203.0.113.1")); out.Blocked != 1 {
		t.Fatalf("not re-blocked at expiry: %+v", out)
	}
}

func TestLegacyEvictsSoonestExpiringFirstInOrder(t *testing.T) {
	cfg := testConfig(100)
	cfg.DenyTempLimit = 2
	l := newTestLegacy(t, cfg, LegacyState{})
	step(t, l, hardBatch(t0, "203.0.113.1"))
	step(t, l, hardBatch(t0.Add(time.Minute), "203.0.113.2"))
	out := step(t, l, hardBatch(t0.Add(2*time.Minute), "203.0.113.3"))
	if !reflect.DeepEqual(out.EvictedIPs, []string{"203.0.113.1"}) || !reflect.DeepEqual(out.EvictionResidences, []time.Duration{2 * time.Minute}) {
		t.Fatalf("%+v", out)
	}

	// Equal expiry: the first entry in insertion order goes.
	tie := newTestLegacy(t, cfg, LegacyState{Entries: []TempEntry{
		{IP: "198.51.100.1", BlockedAt: t0, ExpiresAt: t0.Add(time.Hour)},
		{IP: "198.51.100.2", BlockedAt: t0, ExpiresAt: t0.Add(time.Hour)},
	}})
	if out := step(t, tie, hardBatch(t0, "203.0.113.9")); !reflect.DeepEqual(out.EvictedIPs, []string{"198.51.100.1"}) {
		t.Fatalf("tie: %+v", out)
	}
}

func TestLegacyNeverEvictsPermanentEntries(t *testing.T) {
	cfg := testConfig(100)
	cfg.DenyTempLimit = 1
	l := newTestLegacy(t, cfg, LegacyState{Entries: []TempEntry{
		{IP: "198.51.100.1", BlockedAt: t0.Add(-time.Hour)},
		{IP: "198.51.100.2", BlockedAt: t0, ExpiresAt: t0.Add(time.Hour)},
	}})
	out := step(t, l, hardBatch(t0, "203.0.113.9"))
	if !reflect.DeepEqual(out.EvictedIPs, []string{"198.51.100.2"}) || !l.Blocked("198.51.100.1", t0.Add(1000*time.Hour)) {
		t.Fatalf("%+v", out)
	}
	// Permanent entries occupy no temporary slot.
	cfg.DenyTempLimit = 2
	two := newTestLegacy(t, cfg, LegacyState{Entries: []TempEntry{{IP: "198.51.100.1", BlockedAt: t0}, {IP: "198.51.100.2", BlockedAt: t0, ExpiresAt: t0.Add(time.Hour)}}})
	if out := step(t, two, hardBatch(t0, "203.0.113.9")); out.Evicted != 0 {
		t.Fatalf("permanent entry counted as temporary: %+v", out)
	}
}

func TestLegacyExactExpiryFreesCapacityWithoutEviction(t *testing.T) {
	cfg := testConfig(100)
	cfg.DenyTempLimit = 1
	l := newTestLegacy(t, cfg, LegacyState{})
	step(t, l, hardBatch(t0, "203.0.113.1"))
	if out := step(t, l, hardBatch(t0.Add(time.Hour), "203.0.113.2")); out.Evicted != 0 || out.Blocked != 1 {
		t.Fatalf("%+v", out)
	}
}

func TestLegacyExemptBlocksShareOccupancyNotBudget(t *testing.T) {
	cfg := testConfig(1)
	cfg.DenyTempLimit = 1
	l := newTestLegacy(t, cfg, spentCap(1))
	exempt := Finding{Check: "exempt", Details: "203.0.113.7 30m"}
	out := step(t, l, Batch{At: t0, Findings: []Finding{exempt, exempt}})
	if out.ExemptObserved != 2 || out.ExemptBlocked != 1 || out.Blocked != 0 || l.Snapshot().BlocksThisHour != 1 {
		t.Fatalf("%+v", out)
	}
	if !l.Blocked("203.0.113.7", t0.Add(30*time.Minute-time.Nanosecond)) || l.Blocked("203.0.113.7", t0.Add(30*time.Minute)) {
		t.Fatal("observed lease not applied")
	}
	// An observation of an address already blocked is not a renewal.
	out = step(t, l, Batch{At: t0.Add(10 * time.Minute), Findings: []Finding{exempt}})
	if out.ExemptBlocked != 0 || l.Blocked("203.0.113.7", t0.Add(30*time.Minute)) {
		t.Fatalf("already-blocked observation renewed the lease: %+v", out)
	}
	// It shares the temporary limit with scan blocks.
	next := newTestLegacy(t, cfg, LegacyState{})
	step(t, next, hardBatch(t0, "203.0.113.1"))
	if out := step(t, next, Batch{At: t0.Add(time.Minute), Findings: []Finding{exempt}}); !reflect.DeepEqual(out.EvictedIPs, []string{"203.0.113.1"}) {
		t.Fatalf("exempt block did not share occupancy: %+v", out)
	}
}

func TestLegacyEligibilityFilters(t *testing.T) {
	l := newTestLegacy(t, testConfig(10), LegacyState{})
	out := step(t, l, Batch{At: t0, Findings: []Finding{
		{Check: "critical_only", Severity: "HIGH", Message: "x from 203.0.113.1"},
		{Check: "critical_only", Severity: "CRITICAL", Message: "x from 203.0.113.2"},
		{Check: "unregistered", Severity: "CRITICAL", Message: "x from 203.0.113.3"},
		{Check: "hard", Severity: "CRITICAL", Message: "no address here"},
		{Check: "soft", Severity: "HIGH", Message: "x from 203.0.113.4"},
	}})
	if out.Eligible != 3 || out.MissingIP != 1 || out.ChallengeSkipped != 1 || !reflect.DeepEqual(out.BlockedIPs, []string{"203.0.113.2"}) {
		t.Fatalf("%+v", out)
	}
}

// A challenge does not shield an address from a later hard-block finding.
func TestLegacyChallengeThenHardFindingBlocks(t *testing.T) {
	l := newTestLegacy(t, testConfig(10), LegacyState{})
	soft := Finding{Check: "soft", Severity: "HIGH", Message: "x from 203.0.113.1"}
	if out := step(t, l, Batch{At: t0, Findings: []Finding{soft}}); out.ChallengeSkipped != 1 || out.Blocked != 0 {
		t.Fatalf("%+v", out)
	}
	if out := step(t, l, hardBatch(t0.Add(time.Minute), "203.0.113.1")); out.Blocked != 1 {
		t.Fatalf("%+v", out)
	}
}

func TestLegacyHourKeyUsesTheLiveClockZone(t *testing.T) {
	zone := time.FixedZone("UTC+3", 3*3600)
	cfg := testConfig(1)
	cfg.HourLocation = zone
	l := newTestLegacy(t, cfg, LegacyState{})
	step(t, l, hardBatch(time.Date(2026, 9, 8, 20, 59, 0, 0, time.UTC), "203.0.113.1"))
	if key := l.Snapshot().HourKey; key != "2026-09-08T23" {
		t.Fatalf("hour key = %q", key)
	}
	if out := step(t, l, hardBatch(time.Date(2026, 9, 8, 21, 0, 0, 0, time.UTC), "203.0.113.2")); out.Blocked != 1 || l.Snapshot().HourKey != "2026-09-09T00" {
		t.Fatalf("zone hour boundary: %+v %q", out, l.Snapshot().HourKey)
	}
}

func TestLegacyRefusesBackwardsTimeAndBadConfig(t *testing.T) {
	l := newTestLegacy(t, testConfig(10), LegacyState{})
	step(t, l, Batch{At: t0})
	step(t, l, Batch{At: t0})
	if _, err := l.Step(Batch{At: t0.Add(-time.Nanosecond)}); !errors.Is(err, errTimeBackwards) {
		t.Fatalf("backwards time: %v", err)
	}
	for name, mutate := range map[string]func(*LegacyConfig, *Classifier){
		"zero cap":      func(c *LegacyConfig, _ *Classifier) { c.MaxPerHour = 0 },
		"negative deny": func(c *LegacyConfig, _ *Classifier) { c.DenyTempLimit = -1 },
		"zero ttl":      func(c *LegacyConfig, _ *Classifier) { c.BlockTTL = 0 },
		"zero bound":    func(c *LegacyConfig, _ *Classifier) { c.PendingBound = 0 },
		"zero age":      func(c *LegacyConfig, _ *Classifier) { c.PendingMaxAge = 0 },
		"no zone":       func(c *LegacyConfig, _ *Classifier) { c.HourLocation = nil },
		"no classifier": func(_ *LegacyConfig, k *Classifier) { k.SourceIP = nil },
	} {
		cfg, classes := testConfig(10), testClassifier()
		mutate(&cfg, &classes)
		if _, err := NewLegacy(cfg, classes, LegacyState{}); !errors.Is(err, errLegacyConfig) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	for name, state := range map[string]LegacyState{
		"duplicate pending": {Pending: []PendingEntry{{IP: "203.0.113.1"}, {IP: " 203.0.113.1"}}},
		"duplicate entry":   {Entries: []TempEntry{{IP: "203.0.113.1"}, {IP: "::ffff:203.0.113.1"}}},
		"invalid entry":     {Entries: []TempEntry{{IP: "alice"}}},
	} {
		if _, err := NewLegacy(testConfig(10), testClassifier(), state); !errors.Is(err, errLegacyState) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestLegacyStateCopiesAreIsolated(t *testing.T) {
	initial := LegacyState{Pending: []PendingEntry{{Finding: hard("203.0.113.1"), IP: "203.0.113.1"}}, Entries: []TempEntry{{IP: "198.51.100.1", BlockedAt: t0, ExpiresAt: t0.Add(time.Hour)}}}
	l := newTestLegacy(t, testConfig(10), initial)
	initial.Pending[0].IP = "changed"
	initial.Entries[0].IP = "changed"
	snap := l.Snapshot()
	snap.Pending[0].IP = "changed again"
	snap.Entries[0].IP = "changed again"
	if s := l.Snapshot(); s.Pending[0].IP != "203.0.113.1" || len(s.Entries) != 1 || s.Entries[0].IP != "198.51.100.1" {
		t.Fatalf("state shared with a caller: %+v", s)
	}
}

// The drain order is reproducible for a seed and differs between the seeds
// the baseline uses. The sample and seeds are fixed, so this is exact.
func TestLegacySeedsAreReproducible(t *testing.T) {
	run := func(seed int64) []string {
		cfg := testConfig(5)
		cfg.Seed = seed
		l := newTestLegacy(t, cfg, LegacyState{})
		return step(t, l, hardBatch(t0, ips("203.0.113.", 50)...)).BlockedIPs
	}
	first := run(1)
	if again := run(1); !reflect.DeepEqual(first, again) {
		t.Fatalf("seed 1 not reproducible: %v %v", first, again)
	}
	for _, seed := range []int64{2, 3, 4, 5} {
		if other := run(seed); reflect.DeepEqual(first, other) {
			t.Errorf("seed %d chose the same victims as seed 1: %v", seed, other)
		}
	}
}

// The live high-water mark describes occupancy, so a step that adds nothing
// still reports what is live.
func TestLegacyLiveHighWaterReportsOccupancy(t *testing.T) {
	l := newTestLegacy(t, testConfig(10), LegacyState{Entries: []TempEntry{
		{IP: "198.51.100.1", BlockedAt: t0},
		{IP: "198.51.100.2", BlockedAt: t0, ExpiresAt: t0.Add(time.Hour)},
	}})
	if out := step(t, l, Batch{At: t0}); out.LiveHighWater != 2 {
		t.Fatalf("idle step high water = %d", out.LiveHighWater)
	}
	if out := step(t, l, hardBatch(t0.Add(time.Minute), "203.0.113.1", "203.0.113.2")); out.LiveHighWater != 4 {
		t.Fatalf("high water = %d", out.LiveHighWater)
	}
	if out := step(t, l, Batch{At: t0.Add(2 * time.Hour)}); out.LiveHighWater != 1 {
		t.Fatalf("after expiry high water = %d", out.LiveHighWater)
	}
}
