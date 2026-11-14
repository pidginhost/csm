package mailstats

import (
	"encoding/json"
	"maps"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

func TestFilterVerdictsPreserveLegacyJSONCounts(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	for _, s := range []antispam.Scan{
		{OK: true, Mode: "enforce", Decision: "none"},
		{OK: true, Mode: "enforce", Decision: "tag"},
		{OK: true, Mode: "enforce", Decision: "reject"},
		{OK: true, Mode: "dry-run", Decision: "tag"},
		{OK: true, Mode: "dry-run", Decision: "reject"},
		{OK: true, Mode: "enforce", Decision: "unfiltered"},
		{Mode: "enforce"},
	} {
		c.RecordScan(now, s)
	}
	before := c.Overview(now, now.Add(time.Hour))
	for _, outcome := range []string{FilterDelivered, FilterJunk, FilterRejected, FilterDiscarded, FilterUnmatched} {
		c.RecordFilterVerdict(now, outcome)
	}
	after := c.Overview(now, now.Add(time.Hour))
	for name, pair := range map[string][2]any{
		"totals": {before.Totals, after.Totals},
		"point":  {before.Series[0], after.Series[0]},
	} {
		var old, got map[string]json.RawMessage
		if err := json.Unmarshal([]byte(jsonOf(t, pair[0])), &old); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(jsonOf(t, pair[1])), &got); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"delivered", "junk", "filter_rejected", "discarded", "unmatched"} {
			delete(old, key)
		}
		for key, value := range old {
			if string(got[key]) != string(value) {
				t.Errorf("%s.%s changed from %s to %s", name, key, value, got[key])
			}
		}
		if string(got["filter_rejected"]) != "1" {
			t.Errorf("%s.filter_rejected = %s, want 1", name, got["filter_rejected"])
		}
	}
}

func TestFilterVerdictUnknownOutcomesIgnored(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	c := New(func() time.Time { return now })
	for _, outcome := range []string{"", "error", "malware", "REJECT", "reject:extra", "other"} {
		c.RecordFilterVerdict(now, outcome)
	}
	if len(c.buckets) != 0 || len(c.dirty) != 0 {
		t.Fatalf("unknown outcomes created buckets: %+v, dirty: %v", c.buckets, c.dirty)
	}
}

func TestFilterVerdictsSurviveScanReclassification(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	for _, first := range []bool{false, true} {
		c := New(func() time.Time { return now })
		for _, outcome := range []string{FilterDelivered, FilterJunk, FilterRejected, FilterDiscarded, FilterUnmatched} {
			c.RecordFilterVerdict(now, outcome)
		}
		want := maps.Clone(c.buckets[bucketStart(now)].Scans)
		if first {
			c.RecordQuarantine(now, "message")
		}
		c.RecordScan(now, antispam.Scan{OK: true, Mode: "enforce", Decision: "none", MsgID: "message"})
		if !first {
			c.RecordReject(Reject{At: now, Class: ClassMalware, MsgID: "message"})
		}
		for key, n := range want {
			if got := c.buckets[bucketStart(now)].Scans[key]; got != n {
				t.Errorf("quarantine first=%t: %s = %d, want %d", first, key, got, n)
			}
		}
		ov := c.Overview(now, now.Add(time.Hour))
		if ov.Totals.Scanned != 1 || ov.Totals.Clean != 0 || ov.Totals.Tagged != 0 || ov.Totals.ScanErrors != 0 || ov.Series[0].Malware != 1 {
			t.Fatalf("quarantine first=%t: %+v", first, ov)
		}
	}
}

func TestFilterRejectsSeenAcrossBucketLifecycle(t *testing.T) {
	for _, outcome := range []string{FilterRejected, FilterDiscarded} {
		t.Run(outcome, func(t *testing.T) {
			now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
			c := New(func() time.Time { return now })
			c.RecordFilterVerdict(now.Add(-Retention-time.Second), outcome)
			c.RecordFilterVerdict(now.Add(time.Hour+time.Second), outcome)
			if len(c.buckets) != 0 {
				t.Fatal("out-of-range verdict created a bucket")
			}
			old := now.Add(-Retention + 15*time.Minute)
			c.RecordFilterVerdict(old, outcome)
			if !c.Overview(now, now.Add(time.Hour)).FilterRejectsSeen {
				t.Fatal("kept verdict outside query range was not seen")
			}
			for i := 0; i < bucketLimit; i++ {
				c.RecordFilterVerdict(old.Add(time.Duration(i+1)*15*time.Minute), FilterDelivered)
			}
			if c.Overview(now, now.Add(time.Hour)).FilterRejectsSeen {
				t.Fatal("evicted verdict still seen")
			}
			c.RecordFilterVerdict(now, outcome)
			if !c.Overview(now, now).FilterRejectsSeen {
				t.Fatal("new verdict was not seen for empty query range")
			}
			c.Prune(now.Add(Retention + time.Second))
			if c.Overview(now, now).FilterRejectsSeen {
				t.Fatal("pruned verdict still seen")
			}
		})
	}
}

func TestFilterVerdictsMergeWithStoredScans(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	db := newFakeStore()
	// The bucket schema predates filter verdicts. Unknown scan keys remain
	// readable by the old JSON decoder, and missing filter keys mean zero.
	db.buckets[bucketStart(now)] = []byte(`{"Scans":{"enforce:none":2},"Rejects":{},"Temporary":{}}`)
	c := New(func() time.Time { return now })
	c.RecordFilterVerdict(now, FilterRejected)
	mustLoad(t, c, db, now)
	if err := c.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Scans map[string]int
	}
	if err := json.Unmarshal(db.buckets[bucketStart(now)], &stored); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(stored.Scans, map[string]int{"enforce:none": 2, "stalwart:reject": 1}) {
		t.Fatalf("stored scans %v", stored.Scans)
	}
	c2 := New(func() time.Time { return now })
	c2.RecordFilterVerdict(now, FilterRejected)
	mustLoad(t, c2, db, now)
	if err := c2.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	c3 := New(func() time.Time { return now })
	mustLoad(t, c3, db, now)
	ov := c3.Overview(now, now.Add(time.Hour))
	if ov.Totals.Scanned != 2 || ov.Totals.Clean != 2 || ov.Totals.Tagged != 0 || ov.Totals.ScanErrors != 0 || !ov.FilterRejectsSeen {
		t.Fatalf("reloaded overview %+v", ov)
	}
	if got := c3.buckets[bucketStart(now)].Scans["stalwart:reject"]; got != 2 {
		t.Fatalf("merged rejects = %d, want 2", got)
	}
}
