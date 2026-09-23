package responsereplay

import (
	"reflect"
	"testing"
	"time"
	_ "time/tzdata" // the DST fixture must not depend on the host's zone files
)

func i64(v int64) *int64 { return &v }

func TestDistributionUsesNearestRank(t *testing.T) {
	minutes := func(ms ...int) []int64 {
		out := make([]int64, len(ms))
		for i, m := range ms {
			out[i] = int64(time.Duration(m) * time.Minute)
		}
		return out
	}
	for name, tc := range map[string]struct {
		samples []int64
		want    Distribution
	}{
		"delays":     {minutes(20, 1, 4, 2, 3), Distribution{Count: 5, P50: i64(int64(3 * time.Minute)), P90: i64(int64(20 * time.Minute)), P99: i64(int64(20 * time.Minute)), Max: i64(int64(20 * time.Minute))}},
		"hourly":     {[]int64{0, 1, 3, 2, 9}, Distribution{Count: 5, P50: i64(2), P90: i64(9), P99: i64(9), Max: i64(9)}},
		"residences": {[]int64{60, 120, 180}, Distribution{Count: 3, P50: i64(120), P90: i64(180), P99: i64(180), Max: i64(180)}},
		"singleton":  {[]int64{7}, Distribution{Count: 1, P50: i64(7), P90: i64(7), P99: i64(7), Max: i64(7)}},
		// No samples is no latency, not zero latency.
		"empty": {nil, Distribution{}},
	} {
		input := append([]int64(nil), tc.samples...)
		if got := Distribute(tc.samples); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %+v, want %+v", name, got, tc.want)
		}
		if !reflect.DeepEqual(input, tc.samples) {
			t.Errorf("%s: Distribute reordered its input", name)
		}
	}
}

func TestHourlyBucketsCountEveryElapsedHour(t *testing.T) {
	base := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	times := []time.Time{
		base.Add(time.Hour + time.Minute),
		base.Add(3*time.Hour + 59*time.Minute), base.Add(3 * time.Hour), base.Add(3*time.Hour + time.Second),
		base.Add(4*time.Hour - time.Nanosecond), base.Add(4 * time.Hour),
	}
	// The window runs from the first to the last observation; hours with no
	// blocks are zero, not missing.
	got := HourlyCounts(times, base, base.Add(4*time.Hour))
	if want := []int64{0, 1, 0, 4, 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("buckets = %v, want %v", got, want)
	}
	if got := HourlyCounts(nil, base, base.Add(90*time.Minute)); !reflect.DeepEqual(got, []int64{0, 0}) {
		t.Fatalf("empty window = %v", got)
	}
}

// Buckets are elapsed hours. A zone's repeated or skipped local hour does not
// merge or drop a bucket, though admission still keys its counter on the
// formatted local hour.
func TestHourlyBucketsAcrossDaylightSavingChanges(t *testing.T) {
	zone, err := time.LoadLocation("Europe/Bucharest")
	if err != nil {
		t.Fatal(err)
	}
	// On 2026-10-25 the local hour 03 happens twice: clocks fall back from
	// 04:00 EEST to 03:00 EET at 01:00 UTC.
	fallBack := time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC)
	times := []time.Time{fallBack, fallBack.Add(time.Hour)}
	if a, b := times[0].In(zone).Format("15"), times[1].In(zone).Format("15"); a != b {
		t.Fatalf("fixture hours %s and %s are not a repeated local hour", a, b)
	}
	if got := HourlyCounts(times, times[0], times[1]); !reflect.DeepEqual(got, []int64{1, 1}) {
		t.Fatalf("fall back buckets = %v", got)
	}
	// On 2026-03-29 the local hour 03 does not exist: clocks spring forward
	// from 03:00 EET to 04:00 EEST at 01:00 UTC.
	springForward := time.Date(2026, 3, 29, 0, 30, 0, 0, time.UTC)
	times = []time.Time{springForward, springForward.Add(time.Hour)}
	if got := HourlyCounts(times, times[0], times[1]); !reflect.DeepEqual(got, []int64{1, 1}) {
		t.Fatalf("spring forward buckets = %v", got)
	}
}
