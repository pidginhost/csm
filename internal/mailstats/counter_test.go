package mailstats

import (
	"encoding/json"
	"fmt"
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
	c.RecordQuarantine(now)
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
	c.RecordQuarantine(old)
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
				c.RecordQuarantine(now)
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
