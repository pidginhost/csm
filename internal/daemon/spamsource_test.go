package daemon

import (
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

var spamSourceBase = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

const spamSourceDay = 24 * time.Hour

func TestSpamSourceNeedsTwoOccasions(t *testing.T) {
	tr := newSpamSourceTracker(spamSourceMaxIPs)
	ip := netip.MustParseAddr("198.51.100.1")
	if tr.observe(ip, true, false, spamSourceBase) {
		t.Fatal("first reject qualified")
	}
	// Both fall in the first occasion: the gap counts from the occasion start,
	// not from the latest reject.
	if tr.observe(ip, true, false, spamSourceBase.Add(30*time.Minute)) {
		t.Fatal("reject 30m after the first opened a second occasion")
	}
	if tr.observe(ip, true, false, spamSourceBase.Add(time.Hour-time.Nanosecond)) {
		t.Fatal("reject 1h-1ns after the first opened a second occasion")
	}
	if !tr.observe(ip, true, false, spamSourceBase.Add(time.Hour)) {
		t.Fatal("reject 1h after the first occasion did not qualify")
	}
}

func TestSpamSourceWindowBoundaries(t *testing.T) {
	cases := []struct {
		name          string
		first, second time.Time
		want          bool
	}{
		{"exactly 7 days", spamSourceBase, spamSourceBase.Add(7 * spamSourceDay), true},
		{"7 days plus 1ns", spamSourceBase, spamSourceBase.Add(7*spamSourceDay + time.Nanosecond), false},
		{"day 0 then day 8", spamSourceBase, spamSourceBase.Add(8 * spamSourceDay), false},
		{"day 8 then day 0", spamSourceBase.Add(8 * spamSourceDay), spamSourceBase, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newSpamSourceTracker(spamSourceMaxIPs)
			ip := netip.MustParseAddr("198.51.100.2")
			if tr.observe(ip, true, false, tc.first) {
				t.Fatal("first reject qualified")
			}
			if got := tr.observe(ip, true, false, tc.second); got != tc.want {
				t.Fatalf("second reject = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSpamSourceCleanMailBlocks(t *testing.T) {
	second := spamSourceBase.Add(time.Hour)
	cases := []struct {
		name  string
		clean time.Time
		want  bool
	}{
		{"clean 20 days before", second.Add(-20 * spamSourceDay), false},
		{"clean exactly 30 days before", second.Add(-30 * spamSourceDay), false},
		{"clean 30 days plus 1ns before", second.Add(-30*spamSourceDay - time.Nanosecond), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newSpamSourceTracker(spamSourceMaxIPs)
			ip := netip.MustParseAddr("198.51.100.3")
			if tr.observe(ip, false, true, tc.clean) {
				t.Fatal("clean scan qualified")
			}
			if tr.observe(ip, true, false, spamSourceBase) {
				t.Fatal("first reject qualified")
			}
			if got := tr.observe(ip, true, false, second); got != tc.want {
				t.Fatalf("second occasion = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("older clean keeps the later time", func(t *testing.T) {
		tr := newSpamSourceTracker(spamSourceMaxIPs)
		ip := netip.MustParseAddr("198.51.100.3")
		tr.observe(ip, false, true, second.Add(-20*spamSourceDay))
		tr.observe(ip, false, true, second.Add(-40*spamSourceDay))
		tr.observe(ip, true, false, spamSourceBase)
		if tr.observe(ip, true, false, second) {
			t.Fatal("a late older clean line moved the clean time back")
		}
	})

	t.Run("failed scan is neither", func(t *testing.T) {
		tr := newSpamSourceTracker(spamSourceMaxIPs)
		ip := netip.MustParseAddr("198.51.100.3")
		// Counted as rejects these would be two occasions before the real one.
		for _, at := range []time.Time{spamSourceBase.Add(-2 * time.Hour), spamSourceBase.Add(-time.Hour)} {
			if tr.observe(ip, false, false, at) {
				t.Fatal("failed scan qualified")
			}
		}
		if n := len(tr.snapshot()); n != 0 {
			t.Fatalf("failed scans left %d entries, want 0", n)
		}
		if tr.observe(ip, true, false, spamSourceBase) {
			t.Fatal("one reject after failed scans qualified")
		}
		// Counted as clean mail this would block the second occasion.
		if tr.observe(ip, false, false, spamSourceBase.Add(30*time.Minute)) {
			t.Fatal("failed scan qualified")
		}
		if !tr.observe(ip, true, false, second) {
			t.Fatal("second occasion after a failed scan did not qualify")
		}
		if tr.observe(ip, false, false, second.Add(time.Hour)) {
			t.Fatal("failed scan qualified")
		}
		want := store.SpamSource{Occasions: []time.Time{spamSourceBase, second}, Seen: second}
		if got := tr.snapshot()["198.51.100.3"]; !reflect.DeepEqual(got, want) {
			t.Fatalf("state = %+v, want %+v", got, want)
		}
	})

	t.Run("clean reject in one scan", func(t *testing.T) {
		tr := newSpamSourceTracker(spamSourceMaxIPs)
		ip := netip.MustParseAddr("198.51.100.3")
		if tr.observe(ip, true, false, spamSourceBase) {
			t.Fatal("first reject qualified")
		}
		if tr.observe(ip, true, true, second) {
			t.Fatal("clean reject qualified")
		}
		want := store.SpamSource{Occasions: []time.Time{spamSourceBase, second}, LastClean: second, Seen: second}
		if got := tr.snapshot()["198.51.100.3"]; !reflect.DeepEqual(got, want) {
			t.Fatalf("state = %+v, want %+v", got, want)
		}
	})
}

func TestSpamSourceOutOfOrderReject(t *testing.T) {
	tr := newSpamSourceTracker(spamSourceMaxIPs)
	ip := netip.MustParseAddr("198.51.100.4")
	last := spamSourceBase.Add(2 * time.Hour)
	if tr.observe(ip, true, false, last) {
		t.Fatal("first reject qualified")
	}
	if tr.observe(ip, true, false, spamSourceBase) {
		t.Fatal("older reject qualified")
	}
	want := store.SpamSource{Occasions: []time.Time{last}, Seen: last}
	if got := tr.snapshot()["198.51.100.4"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("state after older reject = %+v, want %+v", got, want)
	}
	// A second occasion opened at the older time would make this qualify.
	if tr.observe(ip, true, false, last.Add(30*time.Minute)) {
		t.Fatal("older reject opened an occasion")
	}
	next := last.Add(time.Hour)
	if !tr.observe(ip, true, false, next) {
		t.Fatal("second occasion did not qualify")
	}
	tr.finish(ip, next, func() bool { return false })
	// A late line from between the two occasions counts only what came before it.
	if tr.observe(ip, true, false, last.Add(45*time.Minute)) {
		t.Fatal("older reject qualified on a later occasion")
	}
}

func TestSpamSourceFinishThrottles(t *testing.T) {
	second := spamSourceBase.Add(time.Hour)

	t.Run("emitted", func(t *testing.T) {
		tr := newSpamSourceTracker(spamSourceMaxIPs)
		ip := netip.MustParseAddr("198.51.100.5")
		emits := 0
		emit := func() bool { emits++; return true }
		if tr.finish(ip, second, emit) {
			t.Fatal("finish without a check in flight = true")
		}
		tr.observe(ip, true, false, spamSourceBase)
		if !tr.observe(ip, true, false, second) {
			t.Fatal("second occasion did not qualify")
		}
		if tr.observe(ip, true, false, second.Add(10*time.Minute)) {
			t.Fatal("observe qualified while a check was in flight")
		}
		if !tr.finish(ip, second, emit) {
			t.Fatal("finish = false, want true")
		}
		if tr.finish(ip, second, emit) {
			t.Fatal("second finish = true, want false")
		}
		if emits != 1 {
			t.Fatalf("emit ran %d times, want 1", emits)
		}
		// The first two would qualify without the throttle: two occasions in
		// the window and no clean mail.
		if tr.observe(ip, true, false, second.Add(23*time.Hour)) {
			t.Fatal("reject 23h after the finding qualified")
		}
		if tr.observe(ip, true, false, second.Add(24*time.Hour-time.Nanosecond)) {
			t.Fatal("reject 24h-1ns after the finding qualified")
		}
		if !tr.observe(ip, true, false, second.Add(24*time.Hour)) {
			t.Fatal("reject 24h after the finding did not qualify")
		}
		// Four occasions were opened; only the latest two are kept.
		want := store.SpamSource{
			Occasions:   []time.Time{second.Add(23 * time.Hour), second.Add(24 * time.Hour)},
			LastFinding: second,
			Seen:        second.Add(24 * time.Hour),
		}
		if got := tr.snapshot()["198.51.100.5"]; !reflect.DeepEqual(got, want) {
			t.Fatalf("state = %+v, want %+v", got, want)
		}
	})

	t.Run("not emitted", func(t *testing.T) {
		tr := newSpamSourceTracker(spamSourceMaxIPs)
		ip := netip.MustParseAddr("198.51.100.6")
		tr.observe(ip, true, false, spamSourceBase)
		if !tr.observe(ip, true, false, second) {
			t.Fatal("second occasion did not qualify")
		}
		emits := 0
		if tr.finish(ip, second, func() bool { emits++; return false }) {
			t.Fatal("finish with emit false = true")
		}
		// The IP still qualifies and is not throttled, but nothing is in flight.
		if tr.finish(ip, second, func() bool { emits++; return true }) {
			t.Fatal("finish without a check in flight = true")
		}
		if emits != 1 {
			t.Fatalf("emit ran %d times, want 1", emits)
		}
		if got := tr.snapshot()["198.51.100.6"].LastFinding; !got.IsZero() {
			t.Fatalf("LastFinding = %v, want zero", got)
		}
		if !tr.observe(ip, true, false, second.Add(time.Minute)) {
			t.Fatal("reject after a failed emit did not qualify again")
		}
	})
}

func TestSpamSourceCleanDuringCheck(t *testing.T) {
	tr := newSpamSourceTracker(spamSourceMaxIPs)
	ip := netip.MustParseAddr("198.51.100.7")
	second := spamSourceBase.Add(time.Hour)
	tr.observe(ip, true, false, spamSourceBase)
	if !tr.observe(ip, true, false, second) {
		t.Fatal("second occasion did not qualify")
	}
	clean := second.Add(time.Minute)
	if tr.observe(ip, false, true, clean) {
		t.Fatal("clean scan qualified")
	}
	emits := 0
	if tr.finish(ip, second, func() bool { emits++; return true }) {
		t.Fatal("finish after clean mail = true")
	}
	if emits != 0 {
		t.Fatalf("emit ran %d times, want 0", emits)
	}
	// The skipped finish still ended the check: once the clean mail ages out
	// two new occasions qualify.
	later := clean.Add(30*spamSourceDay + time.Nanosecond)
	if tr.observe(ip, true, false, later) {
		t.Fatal("first later reject qualified")
	}
	if !tr.observe(ip, true, false, later.Add(time.Hour)) {
		t.Fatal("check stayed in flight after a skipped finish")
	}
}

func TestSpamSourceOneCheckInFlight(t *testing.T) {
	tr := newSpamSourceTracker(spamSourceMaxIPs)
	ip := netip.MustParseAddr("198.51.100.8")
	tr.observe(ip, true, false, spamSourceBase)
	var wg sync.WaitGroup
	var mu sync.Mutex
	started := 0
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tr.observe(ip, true, false, spamSourceBase.Add(time.Hour)) {
				mu.Lock()
				started++
				mu.Unlock()
			}
			tr.snapshot()
		}()
	}
	wg.Wait()
	if started != 1 {
		t.Fatalf("%d concurrent rejects started a check, want 1", started)
	}
}

func TestSpamSourceEvictsLeastRecentlySeen(t *testing.T) {
	ip1 := netip.MustParseAddr("198.51.100.11")
	ip2 := netip.MustParseAddr("198.51.100.12")
	ip3 := netip.MustParseAddr("198.51.100.13")

	t.Run("oldest", func(t *testing.T) {
		tr := newSpamSourceTracker(2)
		tr.observe(ip1, true, false, spamSourceBase)
		tr.observe(ip2, true, false, spamSourceBase.Add(time.Second))
		third := spamSourceBase.Add(2 * time.Second)
		tr.observe(ip3, true, false, third)
		want := map[string]store.SpamSource{
			"198.51.100.12": {Occasions: []time.Time{spamSourceBase.Add(time.Second)}, Seen: spamSourceBase.Add(time.Second)},
			"198.51.100.13": {Occasions: []time.Time{third}, Seen: third},
		}
		if got := tr.snapshot(); !reflect.DeepEqual(got, want) {
			t.Fatalf("state = %+v, want %+v", got, want)
		}
	})

	t.Run("seen again", func(t *testing.T) {
		tr := newSpamSourceTracker(2)
		tr.observe(ip1, true, false, spamSourceBase)
		tr.observe(ip2, true, false, spamSourceBase.Add(time.Second))
		// A reject in the same occasion moves Seen without adding clean mail.
		tr.observe(ip1, true, false, spamSourceBase.Add(2*time.Second))
		fourth := spamSourceBase.Add(3 * time.Second)
		tr.observe(ip3, true, false, fourth)
		want := map[string]store.SpamSource{
			"198.51.100.11": {Occasions: []time.Time{spamSourceBase}, Seen: spamSourceBase.Add(2 * time.Second)},
			"198.51.100.13": {Occasions: []time.Time{fourth}, Seen: fourth},
		}
		if got := tr.snapshot(); !reflect.DeepEqual(got, want) {
			t.Fatalf("state = %+v, want %+v", got, want)
		}
	})
}

func TestSpamSourceEvictsWithoutCleanMailFirst(t *testing.T) {
	type scan struct {
		ip            string
		reject, clean bool
		at            time.Time
	}
	// at is the insert that finds the tracker full.
	at := spamSourceBase.Add(40 * spamSourceDay)
	newcomer := store.SpamSource{Occasions: []time.Time{at}, Seen: at}
	cases := []struct {
		name  string
		scans []scan
		want  map[string]store.SpamSource
	}{
		{
			name: "recent clean mail outlives a later entry with none",
			scans: []scan{
				{"198.51.100.31", false, true, at.Add(-2 * time.Hour)},
				{"198.51.100.32", true, false, at.Add(-time.Hour)},
				{"198.51.100.33", true, false, at},
			},
			want: map[string]store.SpamSource{
				"198.51.100.31": {LastClean: at.Add(-2 * time.Hour), Seen: at.Add(-2 * time.Hour)},
				"198.51.100.33": newcomer,
			},
		},
		{
			name: "clean mail 30 days plus 1ns old counts as none",
			scans: []scan{
				{"198.51.100.31", false, true, at.Add(-2 * time.Hour)},
				{"198.51.100.32", false, true, at.Add(-30*spamSourceDay - time.Nanosecond)},
				{"198.51.100.32", true, false, at.Add(-time.Hour)},
				{"198.51.100.33", true, false, at},
			},
			want: map[string]store.SpamSource{
				"198.51.100.31": {LastClean: at.Add(-2 * time.Hour), Seen: at.Add(-2 * time.Hour)},
				"198.51.100.33": newcomer,
			},
		},
		{
			name: "clean mail exactly 30 days old still counts",
			scans: []scan{
				{"198.51.100.31", false, true, at.Add(-30 * spamSourceDay)},
				{"198.51.100.32", true, false, at.Add(-time.Hour)},
				{"198.51.100.33", true, false, at},
			},
			want: map[string]store.SpamSource{
				"198.51.100.31": {LastClean: at.Add(-30 * spamSourceDay), Seen: at.Add(-30 * spamSourceDay)},
				"198.51.100.33": newcomer,
			},
		},
		{
			name: "all clean evicts the least recently seen",
			scans: []scan{
				{"198.51.100.31", false, true, at.Add(-3 * time.Hour)},
				{"198.51.100.32", false, true, at.Add(-2 * time.Hour)},
				{"198.51.100.31", false, true, at.Add(-time.Hour)},
				{"198.51.100.33", true, false, at},
			},
			want: map[string]store.SpamSource{
				"198.51.100.31": {LastClean: at.Add(-time.Hour), Seen: at.Add(-time.Hour)},
				"198.51.100.33": newcomer,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newSpamSourceTracker(2)
			for _, s := range tc.scans {
				tr.observe(netip.MustParseAddr(s.ip), s.reject, s.clean, s.at)
			}
			if got := tr.snapshot(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("state = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// spamSourceFillClean sends clean mail from n IPs starting at 198.51.100.100,
// the i-th at start plus i seconds, and returns the state each should have.
func spamSourceFillClean(tr *spamSourceTracker, n int, start time.Time) map[string]store.SpamSource {
	m := make(map[string]store.SpamSource, n)
	for i := range n {
		ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(100 + i)})
		at := start.Add(time.Duration(i) * time.Second)
		tr.observe(ip, false, true, at)
		m[ip.String()] = store.SpamSource{LastClean: at, Seen: at}
	}
	return m
}

func spamSourceRejectState(at time.Time) store.SpamSource {
	return store.SpamSource{Occasions: []time.Time{at}, Seen: at}
}

func TestSpamSourceRejectReserveEvictsClean(t *testing.T) {
	at := spamSourceBase.Add(40 * spamSourceDay)
	tr := newSpamSourceTracker(20)
	early := netip.MustParseAddr("198.51.100.41")
	first := at.Add(-2 * time.Hour)
	tr.observe(early, true, false, first)
	// 19 of 20 entries with recent clean mail is above 90 percent.
	want := spamSourceFillClean(tr, 19, at.Add(-time.Hour))
	tr.observe(netip.MustParseAddr("198.51.100.42"), true, false, at)
	delete(want, "198.51.100.100")
	want["198.51.100.41"] = spamSourceRejectState(first)
	want["198.51.100.42"] = spamSourceRejectState(at)
	if got := tr.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("state = %+v, want %+v", got, want)
	}
	if !tr.observe(early, true, false, at.Add(time.Minute)) {
		t.Fatal("reject-only IP kept by the reserve did not qualify on its second occasion")
	}
}

func TestSpamSourceRejectReserveNotReached(t *testing.T) {
	at := spamSourceBase.Add(40 * spamSourceDay)
	cases := []struct {
		name  string
		clean int
	}{
		{"below 90 percent", 17},
		{"exactly 90 percent", 18},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newSpamSourceTracker(20)
			want := spamSourceFillClean(tr, tc.clean, at.Add(-3*time.Hour))
			// Reject-only IPs seen after every clean one, so plain least
			// recently seen order would evict a clean IP instead.
			for i := range 20 - tc.clean {
				ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(41 + i)})
				r := at.Add(-time.Hour + time.Duration(i)*time.Minute)
				tr.observe(ip, true, false, r)
				want[ip.String()] = spamSourceRejectState(r)
			}
			tr.observe(netip.MustParseAddr("198.51.100.50"), true, false, at)
			delete(want, "198.51.100.41")
			want["198.51.100.50"] = spamSourceRejectState(at)
			if got := tr.snapshot(); !reflect.DeepEqual(got, want) {
				t.Fatalf("state = %+v, want %+v", got, want)
			}
		})
	}
}

func TestSpamSourceRejectReserveAging(t *testing.T) {
	at := spamSourceBase.Add(40 * spamSourceDay)
	cases := []struct {
		name    string
		clean   time.Time // clean mail from 198.51.100.43, the oldest clean IP
		evicted string
	}{
		// 18 of 20 count: policy B evicts the least recently seen IP
		// without recent clean mail, the reject-only one.
		{"clean mail 30 days plus 1ns old stops counting", at.Add(-30*spamSourceDay - time.Nanosecond), "198.51.100.41"},
		// 19 of 20 count: the least recently seen clean IP goes.
		{"clean mail exactly 30 days old still counts", at.Add(-30 * spamSourceDay), "198.51.100.43"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newSpamSourceTracker(20)
			rejected := at.Add(-31 * spamSourceDay)
			tr.observe(netip.MustParseAddr("198.51.100.41"), true, false, rejected)
			tr.observe(netip.MustParseAddr("198.51.100.43"), false, true, tc.clean)
			want := spamSourceFillClean(tr, 18, at.Add(-time.Hour))
			tr.observe(netip.MustParseAddr("198.51.100.42"), true, false, at)
			want["198.51.100.41"] = spamSourceRejectState(rejected)
			want["198.51.100.43"] = store.SpamSource{LastClean: tc.clean, Seen: tc.clean}
			want["198.51.100.42"] = spamSourceRejectState(at)
			delete(want, tc.evicted)
			if got := tr.snapshot(); !reflect.DeepEqual(got, want) {
				t.Fatalf("state = %+v, want %+v", got, want)
			}
		})
	}
}

func TestSpamSourceMaxIPs(t *testing.T) {
	if spamSourceMaxIPs != 50_000 {
		t.Fatalf("spamSourceMaxIPs = %d, want 50000", spamSourceMaxIPs)
	}
}

func TestSpamSourceFinishAfterEviction(t *testing.T) {
	tr := newSpamSourceTracker(2)
	ip := netip.MustParseAddr("198.51.100.14")
	tr.observe(ip, true, false, spamSourceBase)
	if !tr.observe(ip, true, false, spamSourceBase.Add(time.Hour)) {
		t.Fatal("second occasion did not qualify")
	}
	tr.observe(netip.MustParseAddr("198.51.100.15"), true, false, spamSourceBase.Add(2*time.Hour))
	tr.observe(netip.MustParseAddr("198.51.100.16"), true, false, spamSourceBase.Add(3*time.Hour))
	emits := 0
	if tr.finish(ip, spamSourceBase.Add(time.Hour), func() bool { emits++; return true }) {
		t.Fatal("finish on an evicted IP = true")
	}
	if emits != 0 {
		t.Fatalf("emit ran %d times, want 0", emits)
	}
}

func TestSpamSourceSnapshotRoundTrip(t *testing.T) {
	v4 := netip.MustParseAddr("198.51.100.9")
	v6 := netip.MustParseAddr("2001:db8::9")
	second := spamSourceBase.Add(time.Hour)
	oldClean := spamSourceBase.Add(-31 * spamSourceDay)

	tr := newSpamSourceTracker(spamSourceMaxIPs)
	tr.observe(v4, false, true, oldClean)
	tr.observe(v4, true, false, spamSourceBase)
	if !tr.observe(v4, true, false, second) {
		t.Fatal("v4 second occasion did not qualify")
	}
	if !tr.finish(v4, second, func() bool { return true }) {
		t.Fatal("v4 finish = false")
	}
	// v6 is left with its check in flight.
	tr.observe(v6, true, false, spamSourceBase)
	if !tr.observe(v6, true, false, second) {
		t.Fatal("v6 second occasion did not qualify")
	}

	want := map[string]store.SpamSource{
		"198.51.100.9": {Occasions: []time.Time{spamSourceBase, second}, LastClean: oldClean, LastFinding: second, Seen: second},
		"2001:db8::9":  {Occasions: []time.Time{spamSourceBase, second}, Seen: second},
	}
	snap := tr.snapshot()
	if !reflect.DeepEqual(snap, want) {
		t.Fatalf("snapshot = %+v, want %+v", snap, want)
	}
	snap["198.51.100.9"].Occasions[0] = time.Time{}
	if got := tr.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("editing a snapshot changed live state: %+v", got)
	}

	loaded := newSpamSourceTracker(spamSourceMaxIPs)
	in := tr.snapshot()
	loaded.load(in, second.Add(time.Hour))
	in["2001:db8::9"].Occasions[0] = time.Time{}
	if got := loaded.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded state = %+v, want %+v", got, want)
	}
	// Without the loaded throttle this would qualify: a new occasion and old
	// clean mail.
	if loaded.observe(v4, true, false, second.Add(time.Hour)) {
		t.Fatal("throttle did not survive the round trip")
	}
	// Same occasion as second, so it qualifies only on both loaded occasions,
	// and only because the check in flight was not carried over.
	if !loaded.observe(v6, true, false, second.Add(30*time.Minute)) {
		t.Fatal("v6 did not qualify after load")
	}

	stale := newSpamSourceTracker(spamSourceMaxIPs)
	stale.load(tr.snapshot(), second.Add(31*spamSourceDay))
	if got := stale.snapshot(); len(got) != 0 {
		t.Fatalf("load 31 days later kept %+v, want none", got)
	}
}

func TestSpamSourceLoadFilters(t *testing.T) {
	now := spamSourceBase
	tr := newSpamSourceTracker(spamSourceMaxIPs)
	tr.load(map[string]store.SpamSource{
		"198.51.100.21":        {Seen: now.Add(-30 * spamSourceDay)},
		"198.51.100.22":        {Seen: now.Add(-30*spamSourceDay - time.Nanosecond)},
		"::ffff:198.51.100.23": {Seen: now},
		"not-an-ip":            {Seen: now},
	}, now)
	want := map[string]store.SpamSource{
		"198.51.100.21": {Seen: now.Add(-30 * spamSourceDay)},
		"198.51.100.23": {Seen: now},
	}
	if got := tr.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded state = %+v, want %+v", got, want)
	}
}
