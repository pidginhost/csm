package checks

import (
	"testing"
	"time"
)

func TestFTPAccumulatorSlowBruteCrossesThresholdOverWindow(t *testing.T) {
	tr := newFTPFailTracker()
	base := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	// 5 failures in minute 0, 5 in minute 1 = 10 within a 30m window.
	for i := 0; i < 5; i++ {
		tr.record("203.0.113.5", base)
	}
	for i := 0; i < 5; i++ {
		tr.record("203.0.113.5", base.Add(time.Minute))
	}
	tr.evict(base.Add(time.Minute), 30)
	offs := tr.offenders(10)
	if len(offs) != 1 || offs[0].IP != "203.0.113.5" || offs[0].Count != 10 {
		t.Fatalf("want one offender 203.0.113.5 count 10, got %+v", offs)
	}
}

func TestFTPAccumulatorEvictionDropsOldBuckets(t *testing.T) {
	tr := newFTPFailTracker()
	base := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		tr.record("198.51.100.7", base)
	}
	// 31 minutes later the bucket is outside a 30m window.
	tr.evict(base.Add(31*time.Minute), 30)
	if offs := tr.offenders(10); len(offs) != 0 {
		t.Fatalf("expected no offenders after eviction, got %+v", offs)
	}
}

func TestFTPAccumulatorKeepsBoundaryBucket(t *testing.T) {
	tr := newFTPFailTracker()
	base := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		tr.record("198.51.100.8", base)
	}
	// Exactly 30 minutes old is still inside a 30m window; only older buckets
	// are evicted.
	tr.evict(base.Add(30*time.Minute), 30)
	offs := tr.offenders(10)
	if len(offs) != 1 || offs[0].IP != "198.51.100.8" || offs[0].Count != 10 {
		t.Fatalf("boundary bucket should remain inside the window, got %+v", offs)
	}
}

func TestFTPAccumulatorCapIPsEvictsOldestActivity(t *testing.T) {
	tr := newFTPFailTracker()
	base := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	// IP "a" active earliest, "c" latest.
	tr.record("203.0.113.1", base)
	tr.record("203.0.113.2", base.Add(time.Minute))
	tr.record("203.0.113.3", base.Add(2*time.Minute))
	tr.capIPs(2)
	if _, ok := tr.Buckets["203.0.113.1"]; ok {
		t.Fatalf("oldest-activity IP should have been evicted; buckets=%v", tr.Buckets)
	}
	if len(tr.Buckets) != 2 {
		t.Fatalf("want 2 tracked IPs after cap, got %d", len(tr.Buckets))
	}
}
