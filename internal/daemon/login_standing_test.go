package daemon

import (
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// standingBase is the clock the standing tests start from; D1 and D2 are
// the two days before it.
var (
	standingBase = time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	standingD1   = standingBase.Add(-50 * time.Hour) // 2026-04-14 10:00
	standingD2   = standingBase.Add(-26 * time.Hour) // 2026-04-15 10:00
)

// hasRow reports whether the index holds a row for ip and mailbox.
func hasRow(s *loginStanding, ip, mailbox string) bool {
	addr, ok := standingAddr(ip)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, held := s.rows[standingKey{addr, normalizeSprayMailbox(mailbox)}]
	return held
}

// An address has standing on a mailbox when its trusted logins there began
// at least a day before the attack, fall on two UTC dates and the latest is
// recent. Nothing logged at or after the attack counts.
func TestLoginStandingRule(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse("2006-01-02 15:04", s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, tc := range []struct {
		name      string
		successes []time.Time
		asOf      time.Time
		want      bool
	}{
		{"two dates a day apart", []time.Time{standingD1, standingD2}, standingBase, true},
		{"first under a day before", []time.Time{at("2026-04-14 13:00"), at("2026-04-15 09:00")}, at("2026-04-15 12:00"), false},
		{"one date", []time.Time{at("2026-04-14 00:30"), at("2026-04-14 23:30")}, at("2026-04-15 01:00"), false},
		{"latest too old", []time.Time{standingD1, standingD2}, standingD2.Add(15 * 24 * time.Hour), false},
		{"latest exactly fourteen days", []time.Time{standingD1, standingD2}, standingD2.Add(14 * 24 * time.Hour), true},
		{"first exactly a day before", []time.Time{at("2026-04-14 12:00"), at("2026-04-15 11:00")}, at("2026-04-15 12:00"), true},
		{"success at asOf ignored", []time.Time{standingD1, standingBase}, standingBase, false},
		{"success after asOf ignored", []time.Time{standingD1, standingBase.Add(5 * time.Minute)}, standingBase, false},
		{"zero asOf", []time.Time{standingD1, standingD2}, time.Time{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &staticClock{t: standingBase.Add(time.Hour)}
			s := newLoginStanding(clock.Now)
			for _, success := range tc.successes {
				s.Note("203.0.113.5", "box@example.com", success)
			}
			if got := s.Has("203.0.113.5", "box@example.com", tc.asOf); got != tc.want {
				t.Fatalf("Has = %v, want %v", got, tc.want)
			}
		})
	}
}

// Standing belongs to one address and one mailbox: IPv4 exact, IPv6 /128,
// mapped IPv4 folded, and one spelling of the mailbox for every caller.
func TestLoginStandingScope(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	for _, day := range []time.Time{standingD1, standingD2} {
		s.Note("203.0.113.5", "box@example.com", day)
		s.Note("2001:db8::1", "v6@example.com", day)
		s.Note("198.51.100.7", " Box@Example.COM.", day)
	}
	for _, tc := range []struct {
		ip, mailbox string
		want        bool
	}{
		{"203.0.113.5", "box@example.com", true},
		{"203.0.113.5", "other@example.com", false},
		{"::ffff:203.0.113.5", "box@example.com", true},
		{"2001:db8::1", "v6@example.com", true},
		{"2001:db8::2", "v6@example.com", false},
		{"198.51.100.7", "box@example.com", true},
		{"198.51.100.7", "BOX@example.com.", true},
	} {
		if got := s.Has(tc.ip, tc.mailbox, standingBase); got != tc.want {
			t.Errorf("Has(%s, %q) = %v, want %v", tc.ip, tc.mailbox, got, tc.want)
		}
	}

	empty := newLoginStanding(clock.Now)
	empty.Note("203.0.113.6", "\xff@example.com", standingD1)
	empty.Note("fe80::1%eth0", "box@example.com", standingD1)
	empty.Note("not-an-address", "box@example.com", standingD1)
	if n := empty.Len(); n != 0 {
		t.Fatalf("Len = %d after invalid notes, want 0", n)
	}
}

// A success stamped in the future counts as now, one older than the row
// window is ignored, and a date keeps its earliest success.
func TestLoginStandingTimestamps(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	s.Note("203.0.113.5", "future@example.com", standingBase.Add(time.Hour))
	s.Note("203.0.113.6", "old@example.com", standingBase.Add(-16*24*time.Hour))
	s.Note("203.0.113.7", "day@example.com", standingD1.Add(5*time.Hour))
	s.Note("203.0.113.7", "day@example.com", standingD1)
	s.Note("203.0.113.7", "day@example.com", standingD1.Add(2*time.Hour))

	upserts, _, _ := s.Changes()
	want := map[string]store.LoginStanding{
		"203.0.113.5 future@example.com": {First: standingBase.Unix(), Days: []int64{standingBase.Unix()}},
		"203.0.113.7 day@example.com":    {First: standingD1.Unix(), Days: []int64{standingD1.Unix()}, Lasts: []int64{standingD1.Add(5 * time.Hour).Unix()}},
	}
	if !reflect.DeepEqual(upserts, want) {
		t.Fatalf("Changes upserts = %v, want %v", upserts, want)
	}
}

// A row keeps the earliest success of its latest fifteen dates, and its
// first success however long ago that was.
func TestLoginStandingKeepsFifteenDates(t *testing.T) {
	start := standingBase.Add(-30 * 24 * time.Hour)
	clock := &staticClock{t: start}
	s := newLoginStanding(clock.Now)
	var days []int64
	for i := range 20 {
		clock.t = start.Add(time.Duration(i) * 24 * time.Hour)
		s.Note("203.0.113.5", "box@example.com", clock.t)
		days = append(days, clock.t.Unix())
	}
	upserts, _, _ := s.Changes()
	got := upserts["203.0.113.5 box@example.com"]
	if got.First != start.Unix() || !slices.Equal(got.Days, days[5:]) {
		t.Fatalf("row = %+v, want first %d and the latest 15 days %v", got, start.Unix(), days[5:])
	}
}

// A full mailbox replaces its own least recently used row; other mailboxes
// keep theirs.
func TestLoginStandingMailboxCap(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	for i := range maxStandingPerMailbox {
		s.Note(fmt.Sprintf("203.0.113.%d", i), "box@example.com", standingD1.Add(time.Duration(i)*time.Minute))
	}
	s.Note("198.51.100.1", "other@example.com", standingD1)
	s.Note("198.51.100.2", "box@example.com", standingD2)

	if hasRow(s, "203.0.113.0", "box@example.com") {
		t.Fatal("the mailbox's least recently used row survived its cap")
	}
	for _, ip := range []string{"203.0.113.1", "203.0.113.255", "198.51.100.2"} {
		if !hasRow(s, ip, "box@example.com") {
			t.Fatalf("row %s lost", ip)
		}
	}
	if !hasRow(s, "198.51.100.1", "other@example.com") {
		t.Fatal("another mailbox's row was evicted")
	}
	if n := s.Len(); n != maxStandingPerMailbox+1 {
		t.Fatalf("Len = %d, want %d", n, maxStandingPerMailbox+1)
	}
}

// A full index refuses new rows instead of evicting live ones, warns once
// an hour, and takes new rows again once old ones expire.
func TestLoginStandingGlobalCap(t *testing.T) {
	logs := captureCSMLog(t)
	t.Cleanup(func() { logs() })
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	for i := range maxStandingRows {
		s.Note("203.0.113.5", fmt.Sprintf("m%d@example.com", i), standingD1)
	}
	s.Note("203.0.113.5", "m0@example.com", standingD2)

	s.Note("198.51.100.9", "new1@example.com", standingBase)
	pruneAt := s.nextPrune
	clock.advance(30 * time.Second)
	s.Note("198.51.100.9", "probe@example.com", standingBase)
	if !s.nextPrune.Equal(pruneAt) {
		t.Fatal("a full index pruned again within a minute")
	}
	clock.advance(30*time.Minute - 30*time.Second)
	s.Note("198.51.100.9", "new2@example.com", standingBase)
	if hasRow(s, "198.51.100.9", "new1@example.com") || hasRow(s, "198.51.100.9", "new2@example.com") {
		t.Fatal("a full index took a new row")
	}
	if !s.Has("203.0.113.5", "m0@example.com", standingBase) {
		t.Fatal("a live row lost its standing to a full index")
	}
	if n := s.Len(); n != maxStandingRows {
		t.Fatalf("Len = %d, want %d", n, maxStandingRows)
	}

	if !s.warnedAt.Equal(standingBase) {
		t.Fatal("full-index warning repeated before an hour")
	}
	clock.advance(30 * time.Minute)
	s.Note("198.51.100.9", "hourly@example.com", clock.Now())
	clock.advance(16 * 24 * time.Hour)
	s.Note("198.51.100.9", "new3@example.com", clock.Now())
	if !hasRow(s, "198.51.100.9", "new3@example.com") {
		t.Fatal("expired rows did not make room")
	}
	if got := strings.Count(logs(), "login standing index full"); got != 2 {
		t.Fatalf("full-index warnings = %d, want 2", got)
	}
}

// Revoking a mailbox removes every address's row for it, however the
// mailbox is spelled, and the removal reaches the store.
func TestLoginStandingRevoke(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	s.Note("203.0.113.5", "box@example.com", standingD1)
	s.Note("198.51.100.1", "box@example.com", standingD1)
	s.Note("203.0.113.5", "other@example.com", standingD1)
	s.Changes()

	s.Revoke(" Box@Example.com.")
	if hasRow(s, "203.0.113.5", "box@example.com") || hasRow(s, "198.51.100.1", "box@example.com") {
		t.Fatal("a revoked mailbox kept a row")
	}
	if !hasRow(s, "203.0.113.5", "other@example.com") {
		t.Fatal("revocation removed another mailbox")
	}
	upserts, deletes, replace := s.Changes()
	if len(upserts) != 0 || replace || !slices.Equal(deletes, []string{"198.51.100.1 box@example.com", "203.0.113.5 box@example.com"}) {
		t.Fatalf("Changes = %v, %v, %v; want the two revoked keys deleted", upserts, deletes, replace)
	}
}

// The index survives a restart through the store, and a load sheds every
// row it cannot trust.
func TestLoginStandingPersistRoundTrip(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	for _, day := range []time.Time{standingD1, standingD2} {
		s.Note("203.0.113.5", "box@example.com", day)
		s.Note("2001:db8::1", "a b@example.com", day)
	}
	if err = db.SaveLoginStanding(s.Changes()); err != nil {
		t.Fatal(err)
	}

	d1, d2 := standingD1.Unix(), standingD2.Unix()
	var sixteen []int64
	for i := 15; i >= 0; i-- {
		sixteen = append(sixteen, standingBase.Add(-time.Duration(i)*24*time.Hour).Unix())
	}
	expired := standingBase.Add(-16 * 24 * time.Hour).Unix()
	invalid := map[string]store.LoginStanding{
		"nonsense":                             {First: d1, Days: []int64{d1}},
		"2001:DB8::1 m@example.com":            {First: d1, Days: []int64{d1}},
		"::ffff:203.0.113.8 m@example.com":     {First: d1, Days: []int64{d1}},
		"203.0.113.9 M@Example.com":            {First: d1, Days: []int64{d1}},
		"203.0.113.10 expired@example.com":     {First: expired, Days: []int64{expired}},
		"203.0.113.11 future@example.com":      {First: d1, Days: []int64{d1, standingBase.Add(time.Hour).Unix()}},
		"203.0.113.12 many@example.com":        {First: sixteen[0], Days: sixteen},
		"203.0.113.13 unsorted@example.com":    {First: d1, Days: []int64{d2, d1}},
		"203.0.113.14 sameday@example.com":     {First: d1, Days: []int64{d1, d1 + 60}},
		"203.0.113.15 beforefirst@example.com": {First: d2, Days: []int64{d1, d2}},
		"203.0.113.16 nodays@example.com":      {First: d1},
		"203.0.113.17 ":                        {First: d1, Days: []int64{d1}},
	}
	if err = db.SaveLoginStanding(invalid, nil, false); err != nil {
		t.Fatal(err)
	}

	saved, err := db.LoadLoginStanding()
	if err != nil {
		t.Fatal(err)
	}
	loaded := newLoginStanding(clock.Now)
	loaded.Load(saved)
	if !loaded.Has("203.0.113.5", "box@example.com", standingBase) || !loaded.Has("2001:db8::1", "a b@example.com", standingBase) {
		t.Fatal("a saved row lost its standing")
	}
	if n := loaded.Len(); n != 2 {
		t.Fatalf("Len = %d, want the 2 valid rows", n)
	}
	upserts, deletes, replace := loaded.Changes()
	var want []string
	for k := range invalid {
		want = append(want, k)
	}
	slices.Sort(want)
	if len(upserts) != 0 || replace || !slices.Equal(deletes, want) {
		t.Fatalf("Changes after load = %v, %v, %v; want every invalid key deleted", upserts, deletes, replace)
	}
}

// A save that fails is retried with the index's current state: a row
// revoked meanwhile is deleted, never written back.
func TestLoginStandingRequeueKeepsRevocation(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	s.Note("203.0.113.5", "box@example.com", standingD1)
	s.Note("198.51.100.1", "other@example.com", standingD1)
	upserts, deletes, replace := s.Changes()
	s.Revoke("box@example.com")
	s.requeue(upserts, deletes, replace)

	upserts, deletes, replace = s.Changes()
	if _, ok := upserts["203.0.113.5 box@example.com"]; ok || replace {
		t.Fatalf("a revoked row was written back: %v", upserts)
	}
	if _, ok := upserts["198.51.100.1 other@example.com"]; !ok {
		t.Fatalf("a held row was not retried: %v", upserts)
	}
	if !slices.Equal(deletes, []string{"203.0.113.5 box@example.com"}) {
		t.Fatalf("deletes = %v, want the revoked row", deletes)
	}
}

// More removals than the index holds rewrite the bucket instead of keeping
// an unbounded delete list.
func TestLoginStandingDeleteOverflowRewrites(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	for i := range maxStandingRows {
		s.Note("203.0.113.5", fmt.Sprintf("m%d@example.com", i), standingD1)
	}
	s.Changes()
	clock.advance(16 * 24 * time.Hour)
	s.Purge()
	upserts, deletes, replace := s.Changes()
	if !replace || len(upserts) != 0 || len(deletes) != 0 {
		t.Fatalf("Changes = %d upserts, %d deletes, replace %v; want an empty rewrite", len(upserts), len(deletes), replace)
	}
}

// Log readers feed the index while dispatch revokes and the saver reads it.
func TestLoginStandingConcurrentUse(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := fmt.Sprintf("203.0.113.%d", g)
			for i := range 500 {
				mailbox := fmt.Sprintf("m%d@example.com", i%4)
				s.Note(ip, mailbox, standingD1)
				s.Has(ip, mailbox, standingBase)
				switch i % 50 {
				case 10:
					s.Revoke(mailbox)
				case 20:
					s.requeue(s.Changes())
				case 30:
					s.Purge()
				}
			}
		}()
	}
	wg.Wait()
	if n := s.Len(); n < 0 || n > 8*4 {
		t.Fatalf("Len = %d", n)
	}
}

// Trackers without an index behave as before.
func TestLoginStandingNil(t *testing.T) {
	var s *loginStanding
	s.Note("203.0.113.5", "box@example.com", standingD1)
	s.Revoke("box@example.com")
	s.Purge()
	s.Load(map[string]store.LoginStanding{"203.0.113.5 box@example.com": {First: 1, Days: []int64{1}}})
	s.requeue(nil, []string{"x"}, true)
	if s.Has("203.0.113.5", "box@example.com", standingBase) || s.Len() != 0 {
		t.Fatal("a nil index reported standing")
	}
	if upserts, deletes, replace := s.Changes(); len(upserts) != 0 || len(deletes) != 0 || replace {
		t.Fatal("a nil index reported changes")
	}
}

func TestLoginStandingLatestSuccessWithinDate(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	first := standingBase.Add(-15 * 24 * time.Hour)
	early := first.Add(24 * time.Hour).Add(-time.Hour)
	late := early.Add(2 * time.Hour)
	for _, at := range []time.Time{first, early, late} {
		s.Note("203.0.113.5", "box@example.com", at)
	}
	if !s.Has("203.0.113.5", "box@example.com", standingBase) {
		t.Fatal("a later success on the same date did not renew standing")
	}
	// Future dates must neither launder this decision nor erase the latest
	// success on the older date that made it valid.
	s.Note("203.0.113.5", "box@example.com", standingBase)
	if !s.Has("203.0.113.5", "box@example.com", standingBase) {
		t.Fatal("a success at asOf erased prior standing")
	}
}

func TestLoginStandingPurgeUsesLatestSuccess(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	s.Note("203.0.113.5", "box@example.com", standingBase.Add(-time.Hour))
	s.Note("203.0.113.5", "box@example.com", standingBase)
	clock.advance(standingKeep)
	s.Purge()
	if !hasRow(s, "203.0.113.5", "box@example.com") {
		t.Fatal("purge removed a row with an unexpired latest success")
	}
	clock.advance(time.Second)
	s.Purge()
	if s.Len() != 0 {
		t.Fatal("purge kept an expired row")
	}
}

func TestLoginStandingMailboxCapUsesLatestSuccess(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	for i := range maxStandingPerMailbox {
		s.Note(fmt.Sprintf("203.0.113.%d", i), "box@example.com", standingD1.Add(time.Duration(i)*time.Minute))
	}
	s.Note("203.0.113.0", "box@example.com", standingD1.Add(5*time.Hour))
	s.Note("198.51.100.1", "box@example.com", standingD2)
	if !hasRow(s, "203.0.113.0", "box@example.com") || hasRow(s, "203.0.113.1", "box@example.com") {
		t.Fatal("mailbox eviction ignored a later success on the same date")
	}
}

func TestLoginStandingLoadCannotUndoLiveState(t *testing.T) {
	clock := &staticClock{t: standingBase}
	key := "203.0.113.5 box@example.com"
	saved := map[string]store.LoginStanding{key: {First: standingD1.Unix(), Days: []int64{standingD1.Unix(), standingD2.Unix()}}}
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("initially empty %v", empty), func(t *testing.T) {
			s := newLoginStanding(clock.Now)
			if !empty {
				s.Load(saved)
			}
			s.Revoke("box@example.com")
			s.Changes()
			s.Load(saved)
			if s.Has("203.0.113.5", "box@example.com", standingBase) {
				t.Fatal("loading a stale snapshot resurrected revoked standing")
			}
			upserts, deletes, replace := s.Changes()
			if len(upserts) != 0 || (!replace && !slices.Equal(deletes, []string{key})) {
				t.Fatal("stale snapshot was not scheduled for deletion on disk")
			}
		})
	}
}

func TestLoginStandingDoesNotRetainLogLines(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range 64 {
		mailbox := fmt.Sprintf("box%d@example.com", i)
		s.Note("203.0.113.5", mailbox, standingD1)
		line := mailbox + strings.Repeat(" ", 1<<20)
		s.Note("203.0.113.5", line[:len(mailbox)], standingD2)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(s)
	if after.HeapAlloc > before.HeapAlloc+(8<<20) {
		t.Fatalf("short mailbox keys retained %d bytes of log lines", after.HeapAlloc-before.HeapAlloc)
	}
}

func TestLoginStandingLatestSuccessSurvivesSave(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	first := standingBase.Add(-standingKeep)
	for _, at := range []time.Time{first, first.Add(23 * time.Hour), first.Add(25 * time.Hour), standingBase} {
		s.Note("203.0.113.5", "box@example.com", at)
	}
	if err = db.SaveLoginStanding(s.Changes()); err != nil {
		t.Fatal(err)
	}
	saved, err := db.LoadLoginStanding()
	if err != nil {
		t.Fatal(err)
	}
	loaded := newLoginStanding(clock.Now)
	loaded.Load(saved)
	if !loaded.Has("203.0.113.5", "box@example.com", standingBase) {
		t.Fatal("save/load lost the last success before asOf")
	}
}

func TestLoginStandingMemoryAtCaps(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range maxStandingRows {
		name := fmt.Sprintf("%0242d@example.com", i)
		for day := standingDays - 1; day >= 0; day-- {
			at := standingBase.Add(-time.Duration(day) * 24 * time.Hour)
			s.Note("2001:db8::1", name, at.Add(-time.Minute))
			s.Note("2001:db8::1", name, at)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(s)
	// Allow map allocator overhead around the 64 MiB target, with maximum
	// length mailbox names and two endpoints on every retained date.
	if after.HeapAlloc > before.HeapAlloc+(72<<20) {
		t.Fatalf("full index retained %.1f MiB", float64(after.HeapAlloc-before.HeapAlloc)/(1<<20))
	}
}

func TestLoginStandingDailyEndpoints(t *testing.T) {
	clock := &staticClock{t: standingBase}
	first := standingBase.Add(-standingKeep)
	early, late := first.Add(23*time.Hour), first.Add(25*time.Hour)
	for _, tc := range []struct {
		name string
		asOf time.Time
		want bool
	}{
		{"before second date", early, false},
		{"inside second date", first.Add(24*time.Hour + time.Second), true},
		{"latest at cutoff", late.Add(standingRecent), true},
		{"latest past cutoff", late.Add(standingRecent + time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newLoginStanding(clock.Now)
			for _, at := range []time.Time{late, first, early} {
				s.Note("203.0.113.5", "box@example.com", at)
			}
			if got := s.Has("203.0.113.5", "box@example.com", tc.asOf); got != tc.want {
				t.Fatalf("Has = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLoginStandingLoadValidatesEndpoints(t *testing.T) {
	first := standingD1.Unix()
	for _, lasts := range [][]int64{{first - 1}, {first + secondsPerDay}, {first, first}, {standingBase.Unix() + 1}} {
		s := newLoginStanding(func() time.Time { return standingBase })
		key := "203.0.113.5 box@example.com"
		s.Load(map[string]store.LoginStanding{key: {First: first, Days: []int64{first}, Lasts: lasts}})
		upserts, deletes, replace := s.Changes()
		if s.Len() != 0 || len(upserts) != 0 || replace || !slices.Equal(deletes, []string{key}) {
			t.Fatalf("invalid endpoints %v survived load", lasts)
		}
	}
}

func TestLoginStandingLoadCapsPreferLatestSuccess(t *testing.T) {
	saved := make(map[string]store.LoginStanding)
	for i := range maxStandingPerMailbox + 1 {
		first := standingD1.Add(time.Duration(i) * time.Second).Unix()
		last := standingD1.Add(time.Duration(maxStandingPerMailbox-i) * time.Minute).Unix()
		// Keep every endpoint within its date and after its first.
		last += 6 * 60 * 60
		saved[fmt.Sprintf("2001:db8::%x box@example.com", i+1)] = store.LoginStanding{First: first, Days: []int64{first}, Lasts: []int64{last}}
	}
	s := newLoginStanding(func() time.Time { return standingBase })
	s.Load(saved)
	if s.Len() != maxStandingPerMailbox || hasRow(s, "2001:db8::101", "box@example.com") || !hasRow(s, "2001:db8::1", "box@example.com") {
		t.Fatal("load did not retain the mailbox's most recently used addresses")
	}
}

// More pending deletions than the budget rewrite the bucket, and a failed
// rewrite retries the index's current contents, including later
// revocations, rather than replaying the captured replacement snapshot.
func TestLoginStandingFailedRewriteRetriesCurrentRows(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	for i := range maxStandingRows {
		s.Note("203.0.113.5", fmt.Sprintf("m%d@example.com", i), standingD1)
	}
	s.Changes()
	for i := range maxStandingPendingDeletes + 1 {
		s.Revoke(fmt.Sprintf("m%d@example.com", i))
	}
	left := maxStandingRows - maxStandingPendingDeletes - 1
	upserts, deletes, replace := s.Changes()
	if !replace || len(deletes) != 0 || len(upserts) != left {
		t.Fatalf("Changes = %d upserts, %d deletes, replace %v; want a rewrite of %d rows", len(upserts), len(deletes), replace, left)
	}
	if _, exists := upserts["203.0.113.5 m0@example.com"]; exists {
		t.Fatal("rewrite restored a revoked row")
	}
	last := fmt.Sprintf("m%d@example.com", maxStandingRows-1)
	s.Revoke(last)
	s.requeue(upserts, deletes, replace)
	upserts, deletes, replace = s.Changes()
	if !replace || len(deletes) != 0 || len(upserts) != left-1 {
		t.Fatal("failed replacement did not schedule the current contents")
	}
	if _, exists := upserts["203.0.113.5 "+last]; exists {
		t.Fatal("failed replacement resurrected a revoked row")
	}
}

// Churn at the cap stays incremental: one revocation and one new row save
// as one delete and one upsert, not a rewrite of the whole bucket.
func TestLoginStandingChurnAtCapStaysIncremental(t *testing.T) {
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	for i := range maxStandingRows {
		s.Note("203.0.113.5", fmt.Sprintf("m%d@example.com", i), standingD1)
	}
	s.Changes()
	s.Revoke("m0@example.com")
	s.Note("198.51.100.9", "new@example.com", standingBase)
	upserts, deletes, replace := s.Changes()
	if replace || len(upserts) != 1 || !slices.Equal(deletes, []string{"203.0.113.5 m0@example.com"}) {
		t.Fatalf("Changes = %d upserts, %v, replace %v; want one upsert and one delete", len(upserts), deletes, replace)
	}
}
