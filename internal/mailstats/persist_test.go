package mailstats

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/store"
)

var _ Store = (*store.DB)(nil)

type fakePut struct {
	buckets     map[int64][]byte
	rejects     map[string][]byte
	pruneBefore int64
}

// fakeStore keeps what the bbolt store keeps, with the same pruning: stats
// keys below the cutoff and gaps that end below it.
type fakeStore struct {
	mu      sync.Mutex
	buckets map[int64][]byte
	rings   map[string][]byte
	gaps    map[int64]int64 // end -> start
	meta    map[string]string
	puts    []fakePut
	putErr  error
	readErr error
	gapErr  error
	metaErr error
	onPut   func() // runs before a write, outside mu
}

func newFakeStore() *fakeStore {
	return &fakeStore{buckets: map[int64][]byte{}, rings: map[string][]byte{}, gaps: map[int64]int64{}, meta: map[string]string{}}
}

func (f *fakeStore) PutMailStats(buckets map[int64][]byte, rejects map[string][]byte, pruneBefore int64) error {
	if f.onPut != nil {
		f.onPut()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return f.putErr
	}
	f.puts = append(f.puts, fakePut{maps.Clone(buckets), maps.Clone(rejects), pruneBefore})
	maps.Copy(f.buckets, buckets)
	maps.Copy(f.rings, rejects)
	maps.DeleteFunc(f.buckets, func(k int64, _ []byte) bool { return k < pruneBefore })
	maps.DeleteFunc(f.gaps, func(end, _ int64) bool { return end < pruneBefore })
	return nil
}

func (f *fakeStore) MailStats() (map[int64][]byte, map[string][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return nil, nil, f.readErr
	}
	return maps.Clone(f.buckets), maps.Clone(f.rings), nil
}

func (f *fakeStore) AddMailStatsGap(start, end int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gapErr != nil {
		return f.gapErr
	}
	f.gaps[end] = start
	return nil
}

func (f *fakeStore) MailStatsGaps(since int64) ([][2]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][2]int64
	for _, end := range slices.Sorted(maps.Keys(f.gaps)) {
		if end > since {
			out = append(out, [2]int64{f.gaps[end], end})
		}
	}
	return out, nil
}

func (f *fakeStore) GetMetaString(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.meta[key]
}

func (f *fakeStore) SetMetaString(key, val string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.metaErr != nil {
		return f.metaErr
	}
	f.meta[key] = val
	return nil
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func bucketKey(at time.Time) int64 { return at.Unix() / BucketSeconds * BucketSeconds }

func mustLoad(t *testing.T, c *Counter, db Store, now time.Time) {
	t.Helper()
	if err := c.Load(db, now); err != nil {
		t.Fatal(err)
	}
}

func TestFlushLoadRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := newFakeStore()
	c := New(func() time.Time { return now })
	if err := c.Load(db, now); err != nil {
		t.Fatal(err)
	}
	c.RecordScan(now.Add(-20*time.Minute), antispam.Scan{OK: true, Mode: "enforce", Score: 152, Decision: "reject", MsgID: "1tAbCd-000001-Ab"})
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "dry-run", Decision: "tag"})
	c.RecordScan(now, antispam.Scan{Mode: "enforce", Decision: "none"})
	c.RecordReject(Reject{At: now.Add(-20 * time.Minute), Class: ClassSpam, IP: "192.0.2.10", Sender: "a@example.com",
		Recipient: "b@example.net", Detail: "rejected", MsgID: "1tAbCd-000001-Ab"})
	c.RecordReject(Reject{At: now, Class: ClassMalware, Detail: "first"})
	c.RecordReject(Reject{At: now, Class: ClassRateLimited, Temporary: true, IP: "198.51.100.7", Detail: "second"})
	c.RecordReject(Reject{At: now, Class: ClassMalware, Detail: "third"})
	c.RecordLoginFailure(now, false, 2)
	c.RecordLoginFailure(now, true, 5)
	c.RecordQuarantine(now)
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	wantOv, wantRj := jsonOf(t, c.Overview(from, to)), jsonOf(t, c.Rejects(from, to, nil, 100))

	now = now.Add(time.Minute)
	c2 := New(func() time.Time { return now })
	if err := c2.Load(db, now); err != nil {
		t.Fatal(err)
	}
	if got := jsonOf(t, c2.Overview(from, to)); got != wantOv {
		t.Errorf("overview\n got %s\nwant %s", got, wantOv)
	}
	if got := jsonOf(t, c2.Rejects(from, to, nil, 100)); got != wantRj {
		t.Errorf("rejects\n got %s\nwant %s", got, wantRj)
	}
}

func TestFlushWritesDirtyBucketsOnly(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := newFakeStore()
	c := New(func() time.Time { return now })
	mustLoad(t, c, db, now)
	scan := antispam.Scan{OK: true, Mode: "enforce", Decision: "none"}
	c.RecordScan(now.Add(-20*time.Minute), scan)
	c.RecordScan(now, scan)
	c.RecordReject(Reject{At: now, Class: ClassSpam})
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	c.RecordScan(now, scan)
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	c.RecordReject(Reject{At: now, Class: ClassMalware})
	if err := c.Flush(db, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	if len(db.puts) != 3 {
		t.Fatalf("%d puts", len(db.puts))
	}
	if p := db.puts[0]; len(p.buckets) != 2 || len(p.rejects) != 1 {
		t.Fatalf("first put %d buckets, %d rings", len(p.buckets), len(p.rejects))
	}
	p := db.puts[1]
	if len(p.buckets) != 1 || len(p.rejects) != 0 || p.pruneBefore != now.Add(-Retention).Unix() {
		t.Fatalf("second put %d buckets, %d rings, prune %d", len(p.buckets), len(p.rejects), p.pruneBefore)
	}
	var b bucket
	if err := json.Unmarshal(p.buckets[bucketKey(now)], &b); err != nil || b.Scans["enforce:none"] != 2 {
		t.Fatalf("second put carries %+v (%v), want the whole bucket", b, err)
	}
	if p := db.puts[2]; len(p.buckets) != 1 || len(p.rejects) != 1 || p.rejects[string(ClassMalware)] == nil {
		t.Fatalf("third put %d buckets, rings %v", len(p.buckets), slices.Collect(maps.Keys(p.rejects)))
	}
	if got := db.meta["mailstats:flushed_at"]; got != now.Add(time.Minute).Format(time.RFC3339) {
		t.Fatalf("flushed_at %q", got)
	}
}

func TestLoadRecordsGapSinceLastFlush(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := newFakeStore()
	db.meta["mailstats:flushed_at"] = now.Add(-30 * time.Minute).Format(time.RFC3339)
	c := New(func() time.Time { return now })
	if err := c.Load(db, now); err != nil {
		t.Fatal(err)
	}
	ov := c.Overview(now.Add(-time.Hour), now)
	if ov.UncountedMinutes != 30 || len(ov.Gaps) != 1 || !ov.Gaps[0].Start.Equal(now.Add(-30*time.Minute)) || !ov.Gaps[0].End.Equal(now) {
		t.Fatalf("uncounted %d, gaps %+v", ov.UncountedMinutes, ov.Gaps)
	}
	if db.gaps[now.Unix()] != now.Add(-30*time.Minute).Unix() || len(db.gaps) != 1 {
		t.Fatalf("stored gaps %v", db.gaps)
	}
}

// A Load retried after a failure must not count the time the counter was
// already counting in memory as a gap: the gap ends where the counter
// started.
func TestLoadGapEndsAtCounterStart(t *testing.T) {
	start := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	now := start
	c := New(func() time.Time { return now })
	db := newFakeStore()
	db.meta["mailstats:flushed_at"] = start.Add(-30 * time.Minute).Format(time.RFC3339)
	now = start.Add(10 * time.Minute)
	mustLoad(t, c, db, now)
	ov := c.Overview(start.Add(-time.Hour), now)
	if ov.UncountedMinutes != 30 || len(ov.Gaps) != 1 || !ov.Gaps[0].End.Equal(start) {
		t.Fatalf("uncounted %d, gaps %+v, want 30 minutes ending at the counter start", ov.UncountedMinutes, ov.Gaps)
	}
	if db.gaps[start.Unix()] != start.Add(-30*time.Minute).Unix() || len(db.gaps) != 1 {
		t.Fatalf("stored gaps %v", db.gaps)
	}
}

func TestLoadNoGapAfterShortStop(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for name, flushed := range map[string]string{
		"90s":    now.Add(-90 * time.Second).Format(time.RFC3339),
		"2m":     now.Add(-2 * time.Minute).Format(time.RFC3339),
		"future": now.Add(5 * time.Minute).Format(time.RFC3339),
		"unset":  "",
		"bad":    "not a time",
	} {
		db := newFakeStore()
		if flushed != "" {
			db.meta["mailstats:flushed_at"] = flushed
		}
		c := New(func() time.Time { return now })
		if err := c.Load(db, now); err != nil {
			t.Fatal(err)
		}
		if ov := c.Overview(now.Add(-time.Hour), now.Add(time.Hour)); ov.UncountedMinutes != 0 || len(ov.Gaps) != 0 || len(db.gaps) != 0 {
			t.Errorf("%s: uncounted %d, gaps %+v, stored %v", name, ov.UncountedMinutes, ov.Gaps, db.gaps)
		}
	}
}

func TestCountingSinceSetOnce(t *testing.T) {
	first := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := newFakeStore()
	c := New(func() time.Time { return first })
	if err := c.Load(db, first); err != nil {
		t.Fatal(err)
	}
	if got := db.meta["mailstats:since"]; got != "2026-10-20T12:00:00Z" {
		t.Fatalf("since %q", got)
	}

	later := first.Add(3 * time.Hour)
	c2 := New(func() time.Time { return later })
	if err := c2.Load(db, later); err != nil {
		t.Fatal(err)
	}
	if got := db.meta["mailstats:since"]; got != "2026-10-20T12:00:00Z" {
		t.Fatalf("since rewritten to %q", got)
	}
	if got := c2.Overview(later.Add(-time.Hour), later).CountingSince; !got.Equal(first) {
		t.Fatalf("counting since %v", got)
	}
}

func TestOverviewClipsGapsToRange(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 10, 20, h, m, 0, 0, time.UTC) }
	db := newFakeStore()
	db.meta["mailstats:since"] = at(10, 30).Format(time.RFC3339)
	db.meta["mailstats:flushed_at"] = at(10, 50).Format(time.RFC3339)
	now := at(11, 20)
	c := New(func() time.Time { return now })
	if err := c.Load(db, now); err != nil {
		t.Fatal(err)
	}

	ov := c.Overview(at(11, 0), at(12, 0))
	if ov.UncountedMinutes != 20 || len(ov.Gaps) != 1 || !ov.Gaps[0].Start.Equal(at(11, 0)) || !ov.Gaps[0].End.Equal(at(11, 20)) {
		t.Fatalf("uncounted %d, gaps %+v", ov.UncountedMinutes, ov.Gaps)
	}
	ov = c.Overview(at(9, 0), at(10, 0))
	if ov.UncountedMinutes != 0 || len(ov.Gaps) != 0 || !ov.CountingSince.Equal(at(10, 30)) {
		t.Fatalf("before the gap: uncounted %d, gaps %+v, since %v", ov.UncountedMinutes, ov.Gaps, ov.CountingSince)
	}
	if got := jsonOf(t, ov.Gaps); got != "[]" {
		t.Fatalf("gaps JSON %s", got)
	}
}

func TestOverviewMergesOverlappingGaps(t *testing.T) {
	// A daemon that stops again before its first flush records a second gap
	// from the same flush time.
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := newFakeStore()
	db.meta["mailstats:flushed_at"] = t0.Format(time.RFC3339)
	for _, now := range []time.Time{t0.Add(30 * time.Minute), t0.Add(35 * time.Minute)} {
		if err := New(func() time.Time { return now }).Load(db, now); err != nil {
			t.Fatal(err)
		}
	}
	now := t0.Add(36 * time.Minute)
	c := New(func() time.Time { return now })
	if err := c.Load(db, now); err != nil {
		t.Fatal(err)
	}
	ov := c.Overview(t0.Add(-time.Hour), t0.Add(time.Hour))
	if ov.UncountedMinutes != 36 || len(ov.Gaps) != 1 || !ov.Gaps[0].Start.Equal(t0) || !ov.Gaps[0].End.Equal(now) {
		t.Fatalf("uncounted %d, gaps %+v", ov.UncountedMinutes, ov.Gaps)
	}
}

func TestLoadSkipsCorruptEntries(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	good := bucketKey(now.Add(-time.Hour))
	db := newFakeStore()
	db.buckets[good] = []byte(`{"Scans":{"enforce:none":3}}`)
	db.buckets[good-BucketSeconds] = []byte(`{"t": bad json`)
	db.buckets[bucketKey(now.Add(-31*24*time.Hour))] = []byte(`{"Scans":{"enforce:none":5}}`)
	db.buckets[good+60] = []byte(`{"Scans":{"enforce:none":7}}`)
	db.buckets[bucketKey(now.Add(2*time.Hour))] = []byte(`{"Scans":{"enforce:none":11}}`)
	entry := func(at time.Time, class Class, detail string) string {
		return fmt.Sprintf(`{"at":%q,"class":%q,"detail":%q,"seq":1}`, at.Format(time.RFC3339), class, detail)
	}
	db.rings["nonsense_class"] = []byte("[" + entry(now, "nonsense_class", "unknown class") + "]")
	db.rings[string(ClassSpam)] = []byte(`[{"at": bad json`)
	db.rings[string(ClassMalware)] = []byte("[" + entry(now.Add(-RingAge-time.Minute), ClassMalware, "past ring age") + "," +
		entry(now, ClassSpam, "wrong ring") + "," + entry(now.Add(2*time.Hour), ClassMalware, "future") + "," +
		entry(now, ClassMalware, "good") + "]")

	c := New(func() time.Time { return now })
	if err := c.Load(db, now); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ov := c.Overview(now.Add(-40*24*time.Hour), now.Add(24*time.Hour))
	if ov.Totals.Scanned != 3 || len(ov.Series) != 1 || ov.Series[0].T != good {
		t.Fatalf("scanned %d, series %+v", ov.Totals.Scanned, ov.Series)
	}
	got := c.Rejects(now.Add(-Retention), now.Add(24*time.Hour), nil, 100)
	if len(got) != 1 || got[0].Detail != "good" {
		t.Fatalf("rejects %+v", got)
	}
}

func TestLoadedBucketAcceptsRecords(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := newFakeStore()
	db.buckets[bucketKey(now)] = []byte(`{"LoginsSMTP":1}`)
	c := New(func() time.Time { return now })
	if err := c.Load(db, now); err != nil {
		t.Fatal(err)
	}
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Decision: "none"})
	c.RecordReject(Reject{At: now, Class: ClassSpam})
	c.RecordReject(Reject{At: now, Class: ClassRateLimited, Temporary: true})
	tot := c.Overview(now.Add(-time.Hour), now.Add(time.Hour)).Totals
	if tot.Scanned != 1 || tot.Rejects[ClassSpam] != 1 || tot.Rejects[ClassRateLimited] != 1 ||
		tot.Temporary[ClassRateLimited] != 1 || tot.LoginsSMTP != 1 {
		t.Fatalf("%+v", tot)
	}
}

func TestLoadAddsToLiveCounts(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := newFakeStore()
	db.buckets[bucketKey(now)] = []byte(`{"Scans":{"enforce:none":2},"Rejects":{"spam":3},"Temporary":{"spam":1},"Quarantined":1}`)
	c := New(func() time.Time { return now })
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Decision: "none"})
	c.RecordReject(Reject{At: now, Class: ClassSpam, Temporary: true})
	if err := c.Load(db, now); err != nil {
		t.Fatal(err)
	}
	tot := c.Overview(now.Add(-time.Hour), now.Add(time.Hour)).Totals
	if tot.Scanned != 3 || tot.Rejects[ClassSpam] != 4 || tot.Temporary[ClassSpam] != 2 || tot.Quarantined != 1 {
		t.Fatalf("%+v", tot)
	}
	// The live bucket was dirty, so the next flush stores the sum.
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	var b bucket
	if err := json.Unmarshal(db.buckets[bucketKey(now)], &b); err != nil || b.Scans["enforce:none"] != 3 || b.Rejects[ClassSpam] != 4 {
		t.Fatalf("stored %+v (%v)", b, err)
	}
}

func TestLoadKeepsNewerLiveRejects(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	db := newFakeStore()
	prev := New(clock)
	mustLoad(t, prev, db, now)
	prev.RecordReject(Reject{At: now.Add(-2 * time.Minute), Class: ClassMalware, Detail: "restored old"})
	prev.RecordReject(Reject{At: now, Class: ClassMalware, Detail: "restored tie"})
	prev.RecordReject(Reject{At: now, Class: ClassSpam, Detail: "restored spam"})
	prev.RecordReject(Reject{At: now.Add(-time.Minute), Class: ClassBadHELO, Detail: "restored helo"})
	if err := prev.Flush(db, now); err != nil {
		t.Fatal(err)
	}

	c := New(clock)
	for i := range RingSize {
		c.RecordReject(Reject{At: now, Class: ClassMalware, Detail: fmt.Sprint("live ", i)})
	}
	c.RecordReject(Reject{At: now, Class: ClassSpam, Detail: "live spam"})
	c.RecordReject(Reject{At: now.Add(-5 * time.Minute), Class: ClassBadHELO, Detail: "live helo"})
	if err := c.Load(db, now); err != nil {
		t.Fatal(err)
	}
	c.RecordReject(Reject{At: now, Class: ClassSpam, Detail: "after load"})

	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	mal := c.Rejects(from, to, []Class{ClassMalware}, 1000)
	if len(mal) != RingSize || mal[0].Detail != fmt.Sprint("live ", RingSize-1) || mal[RingSize-1].Detail != "live 0" {
		t.Fatalf("malware kept %d, newest %q, oldest %q", len(mal), mal[0].Detail, mal[len(mal)-1].Detail)
	}
	var details []string
	for _, r := range c.Rejects(from, to, []Class{ClassSpam, ClassBadHELO}, 10) {
		details = append(details, r.Detail)
	}
	if want := []string{"after load", "live spam", "restored spam", "restored helo", "live helo"}; !slices.Equal(details, want) {
		t.Fatalf("order %q, want %q", details, want)
	}
	// A tie across classes keeps arrival order too: live malware after the
	// restored spam, the spam recorded after Load newest of all.
	all := c.Rejects(now, to, nil, 3)
	if all[0].Detail != "after load" || all[1].Detail != "live spam" || all[2].Detail != "live 199" {
		t.Fatalf("all %+v", all)
	}
}

func TestFlushPrunesRetention(t *testing.T) {
	t0 := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	now := t0
	db := newFakeStore()
	db.meta["mailstats:flushed_at"] = t0.Add(-time.Hour).Format(time.RFC3339)
	c := New(func() time.Time { return now })
	if err := c.Load(db, now); err != nil {
		t.Fatal(err)
	}
	c.RecordScan(t0, antispam.Scan{OK: true, Mode: "enforce", Decision: "none"})
	c.RecordReject(Reject{At: t0, Class: ClassSpam})
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	if len(db.buckets) != 1 || len(db.gaps) != 1 {
		t.Fatalf("setup: %d buckets, %d gaps", len(db.buckets), len(db.gaps))
	}

	now = t0.Add(31 * 24 * time.Hour)
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Decision: "tag"})
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := db.buckets[bucketKey(now)]; len(db.buckets) != 1 || !ok || len(db.gaps) != 0 {
		t.Fatalf("store keeps %d buckets, %d gaps", len(db.buckets), len(db.gaps))
	}
	if string(db.rings[string(ClassSpam)]) != "[]" {
		t.Fatalf("stored spam ring %s", db.rings[string(ClassSpam)])
	}
	if _, ok := c.buckets[bucketKey(now)]; len(c.buckets) != 1 || !ok || len(c.rings[ClassSpam]) != 0 || len(c.gaps) != 0 {
		t.Fatalf("memory keeps %d buckets, %d spam, %d gaps", len(c.buckets), len(c.rings[ClassSpam]), len(c.gaps))
	}
}

func TestFlushPrunesMemoryWhenWriteFails(t *testing.T) {
	t0 := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	now := t0
	db := newFakeStore()
	c := New(func() time.Time { return now })
	mustLoad(t, c, db, now)
	c.RecordScan(t0, antispam.Scan{OK: true, Mode: "enforce", Decision: "none"})
	c.RecordReject(Reject{At: t0, Class: ClassSpam})

	now = t0.Add(31 * 24 * time.Hour)
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Decision: "tag"})
	c.RecordReject(Reject{At: now, Class: ClassMalware})
	db.putErr = errors.New("disk full")
	if err := c.Flush(db, now); err == nil {
		t.Fatal("Flush hid the write error")
	}
	if len(c.buckets) != 1 || len(c.rings[ClassSpam]) != 0 {
		t.Fatalf("memory keeps %d buckets, %d spam", len(c.buckets), len(c.rings[ClassSpam]))
	}
	if _, ok := db.meta["mailstats:flushed_at"]; ok {
		t.Fatal("flushed_at written after a failed write")
	}

	db.putErr = nil
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	p := db.puts[len(db.puts)-1]
	if _, ok := p.buckets[bucketKey(now)]; len(p.buckets) != 1 || !ok {
		t.Fatalf("retry wrote buckets %v", slices.Collect(maps.Keys(p.buckets)))
	}
	if string(p.rejects[string(ClassSpam)]) != "[]" || p.rejects[string(ClassMalware)] == nil {
		t.Fatalf("retry wrote rings %q", p.rejects)
	}
	if db.meta["mailstats:flushed_at"] != now.Format(time.RFC3339) {
		t.Fatalf("flushed_at %q", db.meta["mailstats:flushed_at"])
	}
}

func TestPruneWithoutStore(t *testing.T) {
	t0 := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	now := t0
	c := New(func() time.Time { return now })
	c.RecordScan(t0, antispam.Scan{OK: true, Mode: "enforce", Decision: "none"})
	c.RecordReject(Reject{At: t0, Class: ClassSpam})
	now = t0.Add(RingAge + time.Minute)
	c.Prune(now)
	if len(c.buckets) != 1 || len(c.rings[ClassSpam]) != 0 {
		t.Fatalf("after ring age: %d buckets, %d spam", len(c.buckets), len(c.rings[ClassSpam]))
	}
	now = t0.Add(Retention + BucketSeconds*time.Second)
	c.Prune(now)
	if len(c.buckets) != 0 {
		t.Fatalf("after retention: %d buckets", len(c.buckets))
	}
}

func TestFlushConcurrentWithRecords(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	db := newFakeStore()
	c := New(clock)
	mustLoad(t, c, db, now)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Go(func() {
			for j := 0; j < 200; j++ {
				c.RecordScan(now.Add(-time.Duration(j)*time.Minute), antispam.Scan{OK: true, Mode: "enforce", Decision: "none"})
				c.RecordReject(Reject{At: now, Class: ClassSpam})
			}
		})
	}
	wg.Go(func() {
		for j := 0; j < 50; j++ {
			if err := c.Flush(db, now); err != nil {
				t.Error(err)
			}
		}
	})
	wg.Wait()
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	c2 := New(clock)
	if err := c2.Load(db, now); err != nil {
		t.Fatal(err)
	}
	tot := c2.Overview(now.Add(-24*time.Hour), now.Add(time.Hour)).Totals
	if tot.Scanned != 800 || tot.Rejects[ClassSpam] != 800 {
		t.Fatalf("%+v", tot)
	}
}

func TestFlushesDoNotOverlap(t *testing.T) {
	// A flush that snapshots newer counts must not land before an older
	// flush still writing, or the store ends on the older counts.
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := newFakeStore()
	c := New(func() time.Time { return now })
	mustLoad(t, c, db, now)
	scan := antispam.Scan{OK: true, Mode: "enforce", Decision: "none"}
	entered, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	calls, writing, overlap := 0, 0, false
	db.onPut = func() {
		mu.Lock()
		calls++
		writing++
		overlap = overlap || writing > 1
		first := calls == 1
		mu.Unlock()
		if first {
			close(entered)
			<-release
		}
		mu.Lock()
		writing--
		mu.Unlock()
	}
	c.RecordScan(now, scan)
	var wg sync.WaitGroup
	wg.Go(func() { _ = c.Flush(db, now) })
	<-entered
	c.RecordScan(now, scan)
	wg.Go(func() { _ = c.Flush(db, now) })
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	var b bucket
	if err := json.Unmarshal(db.buckets[bucketKey(now)], &b); err != nil || b.Scans["enforce:none"] != 2 || overlap {
		t.Fatalf("stored %+v (%v), overlap %v", b, err, overlap)
	}
}

func TestSecondLoadIsIgnored(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := newFakeStore()
	db.buckets[bucketKey(now)] = []byte(`{"Scans":{"enforce:none":2}}`)
	db.meta["mailstats:flushed_at"] = now.Add(-30 * time.Minute).Format(time.RFC3339)
	c := New(func() time.Time { return now })
	mustLoad(t, c, db, now)
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Decision: "none"})
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(10 * time.Minute)
	mustLoad(t, c, db, later)

	ov := c.Overview(now.Add(-time.Hour), later)
	if ov.Totals.Scanned != 3 || ov.UncountedMinutes != 30 || len(ov.Gaps) != 1 || len(db.gaps) != 1 {
		t.Fatalf("scanned %d, uncounted %d, gaps %+v, stored gaps %v", ov.Totals.Scanned, ov.UncountedMinutes, ov.Gaps, db.gaps)
	}
}

func TestFlushBeforeLoadKeepsStore(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := newFakeStore()
	db.buckets[bucketKey(now)] = []byte(`{"Scans":{"enforce:none":2}}`)
	c := New(func() time.Time { return now })
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Decision: "none"})
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	if len(db.puts) != 0 || string(db.buckets[bucketKey(now)]) != `{"Scans":{"enforce:none":2}}` {
		t.Fatalf("flush before load wrote %d times, stored %s", len(db.puts), db.buckets[bucketKey(now)])
	}
	if _, ok := db.meta["mailstats:flushed_at"]; ok {
		t.Fatal("flushed_at written before load")
	}

	mustLoad(t, c, db, now)
	if n := c.Overview(now.Add(-time.Hour), now.Add(time.Hour)).Totals.Scanned; n != 3 {
		t.Fatalf("scanned %d after load", n)
	}
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	var b bucket
	if err := json.Unmarshal(db.buckets[bucketKey(now)], &b); err != nil || b.Scans["enforce:none"] != 3 {
		t.Fatalf("stored %+v (%v)", b, err)
	}
}

func TestFailedLoadKeepsCounterInMemory(t *testing.T) {
	t0 := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	now := t0
	db := newFakeStore()
	db.buckets[bucketKey(t0)] = []byte(`{"Scans":{"enforce:none":2}}`)
	db.readErr = errors.New("read failed")
	c := New(func() time.Time { return now })
	if err := c.Load(db, now); err == nil {
		t.Fatal("Load hid the read error")
	}
	c.RecordScan(t0, antispam.Scan{OK: true, Mode: "enforce", Decision: "none"})
	now = t0.Add(31 * 24 * time.Hour)
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Decision: "tag"})
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	if len(db.puts) != 0 || len(db.buckets) != 1 {
		t.Fatalf("flush after a failed load wrote %d times, store has %d buckets", len(db.puts), len(db.buckets))
	}
	if _, ok := c.buckets[bucketKey(now)]; len(c.buckets) != 1 || !ok {
		t.Fatalf("memory keeps %d buckets", len(c.buckets))
	}
}

func TestLoadMetadataFailureKeepsStoreUntilRetry(t *testing.T) {
	for _, stage := range []string{"gap", "since"} {
		t.Run(stage, func(t *testing.T) {
			now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
			db := newFakeStore()
			lastFlush := now.Add(-30 * time.Minute).Format(time.RFC3339)
			db.meta[metaFlushedAt] = lastFlush
			const stored = `{"Scans":{"enforce:none":2}}`
			db.buckets[bucketKey(now)] = []byte(stored)
			writeErr := errors.New("write failed")
			if stage == "gap" {
				db.gapErr = writeErr
			} else {
				db.metaErr = writeErr
			}
			c := New(func() time.Time { return now })
			c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Decision: "none"})
			if err := c.Load(db, now); !errors.Is(err, writeErr) {
				t.Fatalf("Load error = %v, want %v", err, writeErr)
			}
			if got := c.Overview(now.Add(-time.Hour), now.Add(time.Hour)).Totals.Scanned; got != 1 {
				t.Fatalf("failed Load changed live count to %d", got)
			}
			if err := c.Flush(db, now); err != nil {
				t.Errorf("memory-only flush: %v", err)
			}
			if len(db.puts) != 0 || string(db.buckets[bucketKey(now)]) != stored || db.meta[metaFlushedAt] != lastFlush {
				t.Fatal("Flush wrote after a failed Load")
			}
			db.gapErr, db.metaErr = nil, nil
			mustLoad(t, c, db, now)
			mustLoad(t, c, db, now)
			if err := c.Flush(db, now); err != nil {
				t.Fatal(err)
			}
			restarted := New(func() time.Time { return now })
			mustLoad(t, restarted, db, now)
			ov := restarted.Overview(now.Add(-time.Hour), now.Add(time.Hour))
			if ov.Totals.Scanned != 3 || ov.UncountedMinutes != 30 || len(ov.Gaps) != 1 || !ov.CountingSince.Equal(now) {
				t.Fatalf("retry lost or duplicated data: %+v", ov)
			}
		})
	}
}

func TestLoadBoundsBuckets(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := newFakeStore()
	for at := now.Add(-Retention); !at.After(now.Add(time.Hour)); at = at.Add(BucketSeconds * time.Second) {
		db.buckets[bucketKey(at)] = []byte(`{"Quarantined":1}`)
	}
	c := New(func() time.Time { return now })
	c.RecordQuarantine(now)
	mustLoad(t, c, db, now)
	ov := c.Overview(now.Add(-Retention), now.Add(2*time.Hour))
	const limit = 2880
	if len(c.buckets) != limit || len(ov.Series) != limit || ov.Totals.Quarantined != limit+1 {
		t.Fatalf("loaded %d buckets, %d points, %d quarantines", len(c.buckets), len(ov.Series), ov.Totals.Quarantined)
	}
	wantOldest := bucketKey(now.Add(time.Hour)) - (limit-1)*BucketSeconds
	if ov.Series[0].T != wantOldest {
		t.Fatalf("oldest bucket %d, want %d", ov.Series[0].T, wantOldest)
	}
}

func TestRestoredRingTiesSurviveAnotherRestart(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := newFakeStore()
	for i, class := range []Class{ClassSpam, ClassMalware} {
		db.rings[string(class)] = []byte(jsonOf(t, []ringEntry{{Reject: Reject{At: now, Class: class, Detail: string(class)}, Seq: uint64((i + 1) * 50)}}))
	}
	c := New(func() time.Time { return now })
	mustLoad(t, c, db, now)
	c.RecordReject(Reject{At: now, Class: ClassSpam, Detail: "newest"})
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	restarted := New(func() time.Time { return now })
	mustLoad(t, restarted, db, now)
	got := restarted.Rejects(now, now.Add(time.Minute), nil, 10)
	if len(got) != 3 || got[0].Detail != "newest" || got[1].Detail != "malware" || got[2].Detail != "spam" {
		t.Fatalf("arrival order changed after restart: %+v", got)
	}
}

func TestLoadFlushRemovesExpiredStoredRejects(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := newFakeStore()
	db.rings[string(ClassSpam)] = []byte(jsonOf(t, []ringEntry{{Reject: Reject{At: now.Add(-RingAge - time.Second), Class: ClassSpam, Sender: "a@example.com"}, Seq: 1}}))
	c := New(func() time.Time { return now })
	mustLoad(t, c, db, now)
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	if got := string(db.rings[string(ClassSpam)]); got != "[]" {
		t.Fatalf("expired reject details remain stored: %s", got)
	}
}
