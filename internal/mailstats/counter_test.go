package mailstats

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

func TestCounterBucketsByLineTime(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 40, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	c.RecordScan(time.Date(2026, 10, 20, 12, 14, 59, 0, time.UTC), antispam.Scan{OK: true, Mode: "enforce", Decision: "none"})
	c.RecordScan(time.Date(2026, 10, 20, 12, 15, 0, 0, time.UTC), antispam.Scan{OK: true, Mode: "enforce", Decision: "tag"})
	ov := c.Overview(now.Add(-time.Hour), now)
	if len(ov.Series) != 2 || ov.Series[0].T != time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("series %+v", ov.Series)
	}
	if ov.Totals.Scanned != 2 || ov.Totals.Clean != 1 || ov.Totals.Tagged != 1 {
		t.Fatalf("totals %+v", ov.Totals)
	}
}

func TestDryRunNeverCountsAsRejected(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "dry-run", Decision: "reject"})
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "dry-run", Decision: "tag"})
	tot := c.Overview(now.Add(-time.Hour), now.Add(time.Minute)).Totals
	if tot.Rejected != 0 || tot.Tagged != 0 || tot.WouldReject != 1 || tot.WouldTag != 1 || tot.Clean != 2 {
		t.Fatalf("%+v", tot)
	}
}

func TestOverviewTotalsAndPoints(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 10, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	c.RecordReject(Reject{At: now, Class: ClassMalware})
	c.RecordQuarantine(now, "")
	c.RecordReject(Reject{At: now, Class: ClassSenderVerify})
	c.RecordReject(Reject{At: now, Class: ClassRateLimited, Temporary: true})
	c.RecordReject(Reject{At: now, Class: ClassSpam})
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Decision: "reject"})
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Decision: "unfiltered"})
	c.RecordScan(now, antispam.Scan{Mode: "enforce", Decision: "none"})
	c.RecordLoginFailure(now, false, 1)
	c.RecordLoginFailure(now, true, 3)

	ov := c.Overview(now.Add(-time.Hour), now.Add(time.Hour))
	want := Point{T: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC).Unix(), Clean: 1, Rejected: 1, Malware: 2, Other: 1}
	if len(ov.Series) != 1 || ov.Series[0] != want {
		t.Fatalf("series %+v, want [%+v]", ov.Series, want)
	}
	tot := ov.Totals
	if tot.Rejects[ClassRateLimited] != 1 || tot.Rejects[ClassMalware] != 1 || tot.Rejects[ClassSenderVerify] != 1 ||
		tot.Rejects[ClassSpam] != 1 || len(tot.Rejects) != 4 {
		t.Fatalf("rejects %v", tot.Rejects)
	}
	if tot.Temporary[ClassRateLimited] != 1 || len(tot.Temporary) != 1 {
		t.Fatalf("temporary %v", tot.Temporary)
	}
	if tot.Scanned != 3 || tot.Clean != 1 || tot.Unfiltered != 1 || tot.ScanErrors != 1 || tot.Rejected != 1 ||
		tot.Quarantined != 1 || tot.LoginsSMTP != 1 || tot.LoginsMailbox != 3 {
		t.Fatalf("totals %+v", tot)
	}
}

func TestTemporaryRejectsStayOutOfChart(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 10, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	c.RecordReject(Reject{At: now, Class: ClassSenderVerify, Temporary: true})
	c.RecordReject(Reject{At: now, Class: ClassSenderVerify})
	c.RecordReject(Reject{At: now, Class: ClassMalware, Temporary: true})

	ov := c.Overview(now.Add(-time.Hour), now.Add(time.Hour))
	want := Point{T: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC).Unix(), Other: 1}
	if len(ov.Series) != 1 || ov.Series[0] != want {
		t.Fatalf("series %+v, want [%+v]", ov.Series, want)
	}
	tot := ov.Totals
	if tot.Rejects[ClassSenderVerify] != 2 || tot.Rejects[ClassMalware] != 1 {
		t.Fatalf("rejects %v", tot.Rejects)
	}
	if tot.Temporary[ClassSenderVerify] != 1 || tot.Temporary[ClassMalware] != 1 || len(tot.Temporary) != 2 {
		t.Fatalf("temporary %v", tot.Temporary)
	}
}

func TestSpamRejectGetsScoreFromMarker(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Score: 152, Decision: "reject", MsgID: "1tAbCd-000001-Ab"})
	c.RecordReject(Reject{At: now, Class: ClassSpam, MsgID: "1tAbCd-000001-Ab", Detail: "Message rejected as spam"})
	got := c.Rejects(now.Add(-time.Hour), now.Add(time.Hour), nil, 10)
	if len(got) != 1 || got[0].Detail != "score 15.2" {
		t.Fatalf("%+v", got)
	}
}

func TestScoreJoinFormatAndScope(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	scan := func(id string, score int) {
		c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Score: score, Decision: "reject", MsgID: id})
	}
	scan("1tAbCd-000002-Ab", -5)
	scan("1tAbCd-000003-Ab", 0)
	scan("1tAbCd-000004-Ab", 99)
	c.RecordScan(now, antispam.Scan{Mode: "enforce", Decision: "none", MsgID: "1tAbCd-000005-Ab"})
	for _, r := range []Reject{
		{Class: ClassSpam, MsgID: "1tAbCd-000002-Ab", Detail: "a"},
		{Class: ClassSpam, MsgID: "1tAbCd-000003-Ab", Detail: "b"},
		{Class: ClassMalware, MsgID: "1tAbCd-000004-Ab", Detail: "c"},
		{Class: ClassSpam, MsgID: "1tAbCd-000005-Ab", Detail: "d"},
		{Class: ClassSpam, MsgID: "1tAbCd-000006-Ab", Detail: "e"},
	} {
		r.At = now
		c.RecordReject(r)
	}
	var details []string
	for _, r := range c.Rejects(now.Add(-time.Hour), now.Add(time.Hour), nil, 10) {
		details = append(details, r.Detail)
	}
	// Newest inserted first; a malware reject, a failed scan and an unknown
	// message ID keep the reject's own text.
	if got, want := strings.Join(details, "|"), "e|d|c|score 0.0|score -0.5"; got != want {
		t.Fatalf("details %q, want %q", got, want)
	}
}

func TestScoreJoinIsBounded(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	id := func(i int) string { return fmt.Sprintf("1tAbCd-%06d-Ab", i) }
	for i := 0; i <= 1024; i++ {
		c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Score: 152, Decision: "reject", MsgID: id(i)})
	}
	// A marker seen again keeps its place, so it cannot hold a second slot.
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Score: 152, Decision: "reject", MsgID: id(1024)})
	c.RecordReject(Reject{At: now, Class: ClassSpam, MsgID: id(0), Detail: "evicted"})
	c.RecordReject(Reject{At: now, Class: ClassSpam, MsgID: id(1), Detail: "kept"})
	got := c.Rejects(now.Add(-time.Hour), now.Add(time.Hour), []Class{ClassSpam}, 10)
	if len(got) != 2 || got[0].Detail != "score 15.2" || got[1].Detail != "evicted" {
		t.Fatalf("%+v", got)
	}
}

func TestRejectsNewestFirstAcrossClasses(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	t1, t2, t3 := now.Add(-3*time.Minute), now.Add(-2*time.Minute), now.Add(-time.Minute)
	c.RecordReject(Reject{At: t1, Class: ClassSpam})
	c.RecordReject(Reject{At: t2, Class: ClassMalware})
	c.RecordReject(Reject{At: t3, Class: ClassSpam})
	times := func(rs []Reject) []time.Time {
		var out []time.Time
		for _, r := range rs {
			out = append(out, r.At)
		}
		return out
	}
	from, to := now.Add(-time.Hour), now
	both := []Class{ClassSpam, ClassMalware}
	if got := times(c.Rejects(from, to, both, 10)); len(got) != 3 || !got[0].Equal(t3) || !got[1].Equal(t2) || !got[2].Equal(t1) {
		t.Fatalf("all %v", got)
	}
	if got := times(c.Rejects(from, to, both, 2)); len(got) != 2 || !got[0].Equal(t3) || !got[1].Equal(t2) {
		t.Fatalf("limit 2 %v", got)
	}
	if got := times(c.Rejects(from, to, []Class{ClassMalware}, 10)); len(got) != 1 || !got[0].Equal(t2) {
		t.Fatalf("malware %v", got)
	}
}

func TestRejectsRangeTiesAndLimits(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	c.RecordReject(Reject{At: now, Class: ClassSpam, Detail: "first"})
	c.RecordReject(Reject{At: now, Class: ClassMalware, Detail: "second"})
	c.RecordReject(Reject{At: now, Class: ClassBadHELO, Detail: "third"})
	c.RecordReject(Reject{At: now.Add(time.Hour), Class: ClassSpam, Detail: "at to"})

	got := c.Rejects(now, now.Add(time.Hour), []Class{}, 10)
	if len(got) != 3 || got[0].Detail != "third" || got[1].Detail != "second" || got[2].Detail != "first" {
		t.Fatalf("ties %+v", got)
	}
	if got := c.Rejects(now, now.Add(time.Hour), nil, 0); len(got) != 0 {
		t.Fatalf("limit 0 %+v", got)
	}
	if got := c.Rejects(now, now.Add(time.Hour), nil, -1); len(got) != 0 {
		t.Fatalf("limit -1 %+v", got)
	}
	if got := c.Rejects(now.Add(time.Second), now.Add(2*time.Hour), nil, 10); len(got) != 1 || got[0].Detail != "at to" {
		t.Fatalf("range %+v", got)
	}
}

func TestRejectsPastRingAge(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	c.RecordReject(Reject{At: now.Add(-RingAge - time.Minute), Class: ClassSpam, Detail: "never stored"})
	c.RecordReject(Reject{At: now, Class: ClassSpam, Detail: "ages out"})
	if got := c.Rejects(now.Add(-Retention), now.Add(time.Hour), nil, 10); len(got) != 1 || got[0].Detail != "ages out" {
		t.Fatalf("stored %+v", got)
	}
	if n := c.Overview(now.Add(-Retention), now.Add(time.Hour)).Totals.Rejects[ClassSpam]; n != 2 {
		t.Fatalf("counted %d", n)
	}
	now = now.Add(RingAge + time.Second)
	if got := c.Rejects(now.Add(-Retention), now, nil, 10); len(got) != 0 {
		t.Fatalf("read past ring age %+v", got)
	}

	// An old line read late must not push fresh entries out of a full ring.
	for i := 0; i < RingSize; i++ {
		c.RecordReject(Reject{At: now, Class: ClassMalware})
	}
	c.RecordReject(Reject{At: now.Add(-RingAge - time.Minute), Class: ClassMalware})
	if got := c.Rejects(now.Add(-time.Hour), now.Add(time.Hour), []Class{ClassMalware}, 1000); len(got) != RingSize {
		t.Fatalf("fresh malware kept %d", len(got))
	}
}

func TestRejectFloodStaysBounded(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	c.RecordReject(Reject{At: now, Class: ClassSpam, Detail: "keep"})
	for i := 0; i < 10000; i++ {
		c.RecordReject(Reject{At: now, Class: ClassRateLimited, Temporary: true})
	}
	if got := len(c.Rejects(now.Add(-time.Hour), now.Add(time.Hour), []Class{ClassRateLimited}, 1000)); got != RingSize {
		t.Fatalf("rate ring %d", got)
	}
	if got := c.Rejects(now.Add(-time.Hour), now.Add(time.Hour), []Class{ClassSpam}, 10); len(got) != 1 {
		t.Fatalf("spam evicted: %v", got)
	}
	if n := len(c.Overview(now.Add(-time.Hour), now.Add(time.Hour)).Series); n != 1 {
		t.Fatalf("buckets %d", n)
	}
}

func TestRingEvictsOldest(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	for i := 0; i <= RingSize; i++ {
		c.RecordReject(Reject{At: now.Add(time.Duration(i) * time.Second), Class: ClassSpam, Detail: fmt.Sprint(i)})
	}
	got := c.Rejects(now, now.Add(time.Hour), nil, 1000)
	if len(got) != RingSize || got[0].Detail != fmt.Sprint(RingSize) || got[RingSize-1].Detail != "1" {
		t.Fatalf("kept %d, newest %q, oldest %q", len(got), got[0].Detail, got[len(got)-1].Detail)
	}
}

func TestOldRecordsDropped(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	old := now.Add(-31 * 24 * time.Hour)
	c.RecordScan(old, antispam.Scan{OK: true, Mode: "enforce", Decision: "none"})
	c.RecordReject(Reject{At: old, Class: ClassSpam})
	c.RecordLoginFailure(old, true, 2)
	c.RecordQuarantine(old, "")
	ov := c.Overview(now.Add(-40*24*time.Hour), now)
	if ov.Totals.Scanned != 0 || len(ov.Totals.Rejects) != 0 || ov.Totals.LoginsMailbox != 0 || ov.Totals.Quarantined != 0 || len(ov.Series) != 0 {
		t.Fatalf("%+v", ov)
	}
}

func TestCounterConcurrentUse(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Go(func() {
			for j := 0; j < 100; j++ {
				c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Decision: "reject", MsgID: fmt.Sprintf("1tAbCd-%06d-Ab", j)})
				c.RecordReject(Reject{At: now, Class: ClassSpam, MsgID: fmt.Sprintf("1tAbCd-%06d-Ab", j)})
				c.RecordReject(Reject{At: now, Class: ClassRateLimited, Temporary: true})
				c.RecordLoginFailure(now, true, 1)
				c.RecordQuarantine(now, "")
				c.Overview(now.Add(-time.Hour), now.Add(time.Hour))
				c.Rejects(now.Add(-time.Hour), now.Add(time.Hour), nil, 10)
			}
		})
	}
	wg.Wait()
	tot := c.Overview(now.Add(-time.Hour), now.Add(time.Hour)).Totals
	if tot.Rejected != 400 || tot.Rejects[ClassSpam] != 400 || tot.Temporary[ClassRateLimited] != 400 ||
		tot.LoginsMailbox != 400 || tot.Quarantined != 400 {
		t.Fatalf("%+v", tot)
	}
}

func TestOverviewRangeAndJSON(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Decision: "none"})

	if ov := c.Overview(now.Add(30*time.Second), now.Add(time.Hour)); ov.Totals.Scanned != 0 || len(ov.Series) != 0 {
		t.Fatalf("bucket start before from counted: %+v", ov)
	}
	ov := c.Overview(now, now)
	if ov.Totals.Scanned != 0 || len(ov.Series) != 0 || ov.Totals.Rejects == nil || ov.Totals.Temporary == nil || !ov.CountingSince.Equal(now) {
		t.Fatalf("empty range %+v", ov)
	}
	b, err := json.Marshal(ov)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"counting_since":"2026-10-20T12:00:00Z"`, `"rejects":{}`, `"temporary":{}`, `"would_reject":0`, `"logins_smtp":0`, `"uncounted_minutes":0`, `"gaps":[]`, `"series":[]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON lacks %s: %s", want, b)
		}
	}
	b, err = json.Marshal(Overview{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "counting_since") {
		t.Errorf("zero counting_since in JSON: %s", b)
	}
}

func TestFutureRecordsDropped(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	late := now.Add(time.Hour + time.Second)
	c.RecordScan(late, antispam.Scan{OK: true, Mode: "enforce", Decision: "none"})
	c.RecordReject(Reject{At: late, Class: ClassSpam})
	c.RecordLoginFailure(late, true, 2)
	c.RecordQuarantine(late, "")
	c.RecordScan(now.Add(time.Hour), antispam.Scan{OK: true, Mode: "enforce", Decision: "tag"})

	ov := c.Overview(now.Add(-time.Hour), now.Add(48*time.Hour))
	if ov.Totals.Scanned != 1 || ov.Totals.Tagged != 1 || len(ov.Totals.Rejects) != 0 || ov.Totals.LoginsMailbox != 0 ||
		ov.Totals.Quarantined != 0 || len(ov.Series) != 1 {
		t.Fatalf("%+v", ov)
	}
	if got := c.Rejects(now.Add(-time.Hour), now.Add(48*time.Hour), nil, 10); len(got) != 0 {
		t.Fatalf("ring %+v", got)
	}
}

func TestLoginFailureWithoutCountIgnored(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	c.RecordLoginFailure(now, true, 0)
	c.RecordLoginFailure(now, false, -3)
	ov := c.Overview(now.Add(-time.Hour), now.Add(time.Hour))
	if len(ov.Series) != 0 || ov.Totals.LoginsSMTP != 0 || ov.Totals.LoginsMailbox != 0 {
		t.Fatalf("%+v", ov)
	}
}

func TestRejectsWithoutLimitMarshalsEmpty(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	c.RecordReject(Reject{At: now, Class: ClassSpam})
	for _, limit := range []int{0, -1} {
		b, err := json.Marshal(c.Rejects(now.Add(-time.Hour), now.Add(time.Hour), nil, limit))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "[]" {
			t.Errorf("limit %d: %s", limit, b)
		}
	}
}

func TestBucketsStayBoundedWithoutFlush(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	const limit = 2880
	for i := 0; i < limit+10; i++ {
		c.RecordQuarantine(now, "")
		if len(c.buckets) > limit || len(c.dirty) > limit {
			t.Fatalf("record %d: %d buckets, %d dirty, limit %d", i, len(c.buckets), len(c.dirty), limit)
		}
		now = now.Add(BucketSeconds * time.Second)
	}
	// Late records cannot evict more recent buckets from a full counter.
	now = now.Add(-BucketSeconds * time.Second)
	c.RecordQuarantine(now.Add(-Retention), "")
	if _, ok := c.buckets[bucketKey(now.Add(-Retention))]; ok {
		t.Fatal("late record evicted a newer bucket")
	}
	now = now.Add(BucketSeconds * time.Second)
	for i := 0; i <= 4; i++ {
		c.RecordQuarantine(now.Add(time.Duration(i)*BucketSeconds*time.Second), "")
	}
	ov := c.Overview(now.Add(-2*Retention), now.Add(2*time.Hour))
	wantOldest := bucketKey(now.Add(time.Hour)) - (limit-1)*BucketSeconds
	if len(ov.Series) != limit {
		t.Fatalf("kept %d buckets, want %d", len(ov.Series), limit)
	}
	if ov.Series[0].T != wantOldest || ov.Totals.Quarantined != limit {
		t.Fatalf("kept %d buckets, first %d, quarantined %d", len(ov.Series), ov.Series[0].T, ov.Totals.Quarantined)
	}
}

func TestRejectRingKeepsNewestByEventTime(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	for i := 0; i < RingSize; i++ {
		c.RecordReject(Reject{At: now.Add(-time.Duration(i) * time.Minute), Class: ClassSpam, Detail: fmt.Sprint(i)})
	}
	c.RecordReject(Reject{At: now.Add(-6 * 24 * time.Hour), Class: ClassSpam, Detail: "late oldest"})
	c.RecordReject(Reject{At: now.Add(-30 * time.Second), Class: ClassSpam, Detail: "late recent"})
	got := c.Rejects(now.Add(-RingAge), now.Add(time.Minute), nil, RingSize+1)
	if len(got) != RingSize {
		t.Fatalf("kept %d rejects, want %d", len(got), RingSize)
	}
	if got[0].Detail != "0" || got[1].Detail != "late recent" || got[len(got)-1].Detail != "198" {
		t.Fatalf("ring lost newer rejects: first %q, second %q, last %q", got[0].Detail, got[1].Detail, got[len(got)-1].Detail)
	}
	if n := c.Overview(now.Add(-RingAge), now.Add(time.Minute)).Totals.Rejects[ClassSpam]; n != RingSize+2 {
		t.Fatalf("counted %d rejects, want %d", n, RingSize+2)
	}
}

// checkMalwareMove fails t unless the overview of the hour before now has
// exactly these totals and series.
func checkMalwareMove(t *testing.T, c *Counter, now time.Time, want Totals, wantSeries []Point) {
	t.Helper()
	ov := c.Overview(now.Add(-time.Hour), now)
	if !reflect.DeepEqual(ov.Totals, want) {
		t.Errorf("totals %+v\nwant   %+v", ov.Totals, want)
	}
	if !slices.Equal(ov.Series, wantSeries) {
		t.Errorf("series %+v\nwant   %+v", ov.Series, wantSeries)
	}
}

// Exim logs the scan marker in the DATA ACL, before the antivirus deny, so a
// malware reject follows the scan of its message. That scan stays scanned
// but no longer counts as clean, tagged, rejected, would-tag or would-reject.
func TestMalwareRejectMovesScanOutOfClean(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 40, 0, 0, time.UTC)
	scanAt := time.Date(2026, 10, 20, 12, 14, 59, 0, time.UTC)
	const id = "1tAbCd-000001-Ab"
	for _, s := range []antispam.Scan{
		{OK: true, Mode: "enforce", Policy: "on", Decision: "none"},
		{OK: true, Mode: "enforce", Policy: "off", Decision: "unfiltered"},
		{OK: true, Mode: "enforce", Policy: "on", Decision: "tag"},
		{OK: true, Mode: "enforce", Policy: "on", Decision: "reject"},
		{OK: true, Mode: "dry-run", Policy: "on", Decision: "tag"},
		{OK: true, Mode: "dry-run", Policy: "on", Decision: "reject"},
	} {
		t.Run(s.Mode+":"+s.Decision, func(t *testing.T) {
			c := New(func() time.Time { return now })
			s.MsgID = id
			c.RecordScan(scanAt, s)
			if tot := c.Overview(now.Add(-time.Hour), now).Totals; tot.Scanned != 1 {
				t.Fatalf("before the reject: %+v", tot)
			}
			// The reject lands in the next bucket.
			c.RecordReject(Reject{At: scanAt.Add(time.Second), Class: ClassMalware, MsgID: id})
			checkMalwareMove(t, c, now,
				Totals{Scanned: 1, Rejects: map[Class]int{ClassMalware: 1}, Temporary: map[Class]int{}},
				[]Point{{T: bucketKey(scanAt)}, {T: bucketKey(scanAt) + BucketSeconds, Malware: 1}})
		})
	}
}

// The spool watcher quarantines a message after Exim accepted it, so its
// scan marker counted it as clean.
func TestQuarantineMovesScanOutOfClean(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 40, 0, 0, time.UTC)
	scanAt := time.Date(2026, 10, 20, 12, 14, 59, 0, time.UTC)
	const id = "1tAbCd-000001-Ab"
	c := New(func() time.Time { return now })
	c.RecordScan(scanAt, antispam.Scan{OK: true, Mode: "enforce", Policy: "on", Decision: "none", MsgID: id})
	c.RecordQuarantine(scanAt.Add(time.Second), id)
	checkMalwareMove(t, c, now,
		Totals{Scanned: 1, Quarantined: 1, Rejects: map[Class]int{}, Temporary: map[Class]int{}},
		[]Point{{T: bucketKey(scanAt)}, {T: bucketKey(scanAt) + BucketSeconds, Malware: 1}})
}

// The spool watcher can quarantine a message before the log watcher reads
// its scan marker. The scan then counts as malware straight away.
func TestQuarantineBeforeScanCountsMalware(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 40, 0, 0, time.UTC)
	scanAt := time.Date(2026, 10, 20, 12, 14, 59, 0, time.UTC)
	const id = "1tAbCd-000001-Ab"
	for _, s := range []antispam.Scan{
		{OK: true, Mode: "enforce", Policy: "on", Decision: "none"},
		{OK: true, Mode: "enforce", Policy: "off", Decision: "unfiltered"},
		{OK: true, Mode: "enforce", Policy: "on", Decision: "tag"},
		{OK: true, Mode: "enforce", Policy: "on", Decision: "reject"},
		{OK: true, Mode: "dry-run", Policy: "on", Decision: "tag"},
		{OK: true, Mode: "dry-run", Policy: "on", Decision: "reject"},
	} {
		t.Run(s.Mode+":"+s.Decision, func(t *testing.T) {
			c := New(func() time.Time { return now })
			c.RecordQuarantine(scanAt.Add(time.Second), id)
			s.MsgID = id
			c.RecordScan(scanAt, s)
			checkMalwareMove(t, c, now,
				Totals{Scanned: 1, Quarantined: 1, Rejects: map[Class]int{}, Temporary: map[Class]int{}},
				[]Point{{T: bucketKey(scanAt)}, {T: bucketKey(scanAt) + BucketSeconds, Malware: 1}})
		})
	}
}

// A quarantine read before the scan already took that scan out of clean, so
// a later malware reject of the message moves nothing. Another clean scan in
// the same bucket stays clean.
func TestQuarantineScanRejectMovesOnce(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 10, 0, 0, time.UTC)
	const id = "1tAbCd-000001-Ab"
	c := New(func() time.Time { return now })
	c.RecordQuarantine(now, id)
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Policy: "on", Decision: "none", MsgID: id})
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Policy: "on", Decision: "none", MsgID: "1tAbCd-000002-Ab"})
	c.RecordReject(Reject{At: now, Class: ClassMalware, MsgID: id})
	checkMalwareMove(t, c, now.Add(time.Minute),
		Totals{Scanned: 2, Clean: 1, Quarantined: 1, Rejects: map[Class]int{ClassMalware: 1}, Temporary: map[Class]int{}},
		[]Point{{T: bucketKey(now), Clean: 1, Malware: 2}})
}

// A repeated malware line, or a reject and a quarantine of one message, moves
// its scan once. Another clean scan in the same bucket stays clean.
func TestMalwareMoveOnlyOnce(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 10, 0, 0, time.UTC)
	const id = "1tAbCd-000001-Ab"
	c := New(func() time.Time { return now })
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Policy: "on", Decision: "none", MsgID: id})
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Policy: "on", Decision: "none", MsgID: "1tAbCd-000002-Ab"})
	c.RecordReject(Reject{At: now, Class: ClassMalware, MsgID: id})
	c.RecordReject(Reject{At: now, Class: ClassMalware, MsgID: id})
	c.RecordQuarantine(now, id)
	checkMalwareMove(t, c, now.Add(time.Minute),
		Totals{Scanned: 2, Clean: 1, Quarantined: 1, Rejects: map[Class]int{ClassMalware: 2}, Temporary: map[Class]int{}},
		[]Point{{T: bucketKey(now), Clean: 1, Malware: 3}})
}

// Without a known scan of the message nothing moves and the malware still
// counts. A failed scan never counted as clean, so it stays a scan error.
func TestMalwareMoveUnknownMsgID(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 10, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Policy: "on", Decision: "none", MsgID: "1tAbCd-000001-Ab"})
	c.RecordScan(now, antispam.Scan{Mode: "enforce", Policy: "on", Decision: "none", MsgID: "1tAbCd-000002-Ab"})
	c.RecordReject(Reject{At: now, Class: ClassMalware, MsgID: "1tAbCd-000002-Ab"})
	c.RecordReject(Reject{At: now, Class: ClassMalware, MsgID: "1tAbCd-000003-Ab"})
	c.RecordReject(Reject{At: now, Class: ClassMalware})
	c.RecordQuarantine(now, "1tAbCd-000004-Ab")
	c.RecordQuarantine(now, "")
	checkMalwareMove(t, c, now.Add(time.Minute),
		Totals{Scanned: 2, Clean: 1, ScanErrors: 1, Quarantined: 2, Rejects: map[Class]int{ClassMalware: 3}, Temporary: map[Class]int{}},
		[]Point{{T: bucketKey(now), Clean: 1, Malware: 5}})
}

// A temporary reject defers the message rather than deciding it, so its scan
// stays where it counted until a permanent reject follows.
func TestTemporaryMalwareRejectDoesNotMove(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 10, 0, 0, time.UTC)
	const id = "1tAbCd-000001-Ab"
	c := New(func() time.Time { return now })
	c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Policy: "on", Decision: "none", MsgID: id})
	c.RecordReject(Reject{At: now, Class: ClassMalware, MsgID: id, Temporary: true})
	checkMalwareMove(t, c, now.Add(time.Minute),
		Totals{Scanned: 1, Clean: 1, Rejects: map[Class]int{ClassMalware: 1}, Temporary: map[Class]int{ClassMalware: 1}},
		[]Point{{T: bucketKey(now), Clean: 1}})

	c.RecordReject(Reject{At: now, Class: ClassMalware, MsgID: id})
	checkMalwareMove(t, c, now.Add(time.Minute),
		Totals{Scanned: 1, Rejects: map[Class]int{ClassMalware: 2}, Temporary: map[Class]int{ClassMalware: 1}},
		[]Point{{T: bucketKey(now), Malware: 1}})
}

// The scan's bucket can be gone by the time the malware line is read:
// pruned past retention, or evicted from a full counter and made again,
// empty, by a later record. The malware still counts and no scan count
// goes below zero.
func TestMalwareMoveSkipsDroppedScanBucket(t *testing.T) {
	start := time.Date(2026, 10, 20, 12, 10, 0, 0, time.UTC)
	const id = "1tAbCd-000001-Ab"
	scan := antispam.Scan{OK: true, Mode: "enforce", Policy: "on", Decision: "none", MsgID: id}

	now := start
	c := New(func() time.Time { return now })
	c.RecordScan(now, scan)
	now = now.Add(Retention + time.Hour)
	c.Prune(now)
	c.RecordReject(Reject{At: now, Class: ClassMalware, MsgID: id})
	c.RecordQuarantine(now, id)
	checkMalwareMove(t, c, now.Add(time.Minute),
		Totals{Quarantined: 1, Rejects: map[Class]int{ClassMalware: 1}, Temporary: map[Class]int{}},
		[]Point{{T: bucketKey(now), Malware: 2}})

	now = start
	c = New(func() time.Time { return now })
	c.RecordScan(now, scan)
	delete(c.buckets, bucketKey(now))
	c.RecordQuarantine(now, id)
	checkMalwareMove(t, c, now.Add(time.Minute),
		Totals{Quarantined: 1, Rejects: map[Class]int{}, Temporary: map[Class]int{}},
		[]Point{{T: bucketKey(now), Malware: 1}})
}

// Sends sum by account across buckets, most messages first and then by
// name. A submitter that resolved to no account counts in the total but is
// not a row, and the row limit leaves the totals whole.
func TestRecordSendSumsByAccount(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 40, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	early := now.Add(-30 * time.Minute)
	for _, s := range []struct {
		at      time.Time
		account string
	}{
		{early, "bravo"}, {early, "bravo"}, {now, "bravo"},
		{now, "charlie"}, {now, "charlie"}, {now, "charlie"},
		{early, "delta"}, {now, "alpha"}, {early, ""}, {now, ""},
	} {
		c.RecordSend(s.at, s.account)
	}
	from, to := now.Add(-time.Hour), now.Add(time.Hour)

	want := SendersReport{Accounts: []AccountSends{{"bravo", 3}, {"charlie", 3}, {"alpha", 1}, {"delta", 1}}, Total: 10, Unresolved: 2}
	for _, n := range []int{0, -1, 4, 9} {
		if got := c.TopSenders(from, to, n); !reflect.DeepEqual(got, want) {
			t.Fatalf("n=%d: %+v, want %+v", n, got, want)
		}
	}
	if got := jsonOf(t, c.TopSenders(from, to, 1)); got != `{"accounts":[{"account":"bravo","messages":3}],"total":10,"unresolved":2}` {
		t.Fatalf("n=1: %s", got)
	}
	// Only the later bucket starts in the range.
	late := SendersReport{Accounts: []AccountSends{{"charlie", 3}, {"alpha", 1}, {"bravo", 1}}, Total: 6, Unresolved: 1}
	if got := c.TopSenders(time.Unix(bucketStart(now), 0), to, 0); !reflect.DeepEqual(got, late) {
		t.Fatalf("later bucket: %+v, want %+v", got, late)
	}
	if got := jsonOf(t, New(time.Now).TopSenders(from, to, 0)); got != `{"accounts":[],"total":0,"unresolved":0}` {
		t.Fatalf("empty: %s", got)
	}
}
