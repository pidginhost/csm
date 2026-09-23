package responsereplay

import (
	"maps"
	"math"
	"slices"
	"time"
)

// Distribution summarises samples by nearest rank: the p-th percentile is
// the ceil(p*N)-th smallest sample. Every statistic is nil when there are no
// samples; an empty population has no latency, not zero latency.
type Distribution struct {
	Count int    `json:"count"`
	P50   *int64 `json:"p50,omitempty"`
	P90   *int64 `json:"p90,omitempty"`
	P99   *int64 `json:"p99,omitempty"`
	Max   *int64 `json:"max,omitempty"`
}

// Distribute summarises samples without reordering them.
func Distribute(samples []int64) Distribution {
	if len(samples) == 0 {
		return Distribution{}
	}
	sorted := slices.Sorted(slices.Values(samples))
	rank := func(p float64) *int64 {
		v := sorted[int(math.Ceil(p*float64(len(sorted))))-1]
		return &v
	}
	return Distribution{Count: len(sorted), P50: rank(0.50), P90: rank(0.90), P99: rank(0.99), Max: rank(1)}
}

// HourlyCounts counts times into consecutive elapsed hours, from the hour
// holding first to the hour holding last. Hours with nothing in them are
// zero. Buckets are elapsed hours, so a repeated or skipped local hour
// neither merges nor drops one; admission's own counter still keys on the
// formatted local hour.
func HourlyCounts(times []time.Time, first, last time.Time) []int64 {
	start := hourIndex(first)
	counts := make([]int64, int(hourIndex(last)-start)+1)
	for _, t := range times {
		if i := int(hourIndex(t) - start); i >= 0 && i < len(counts) {
			counts[i]++
		}
	}
	return counts
}

// HourlyDistribution includes empty elapsed hours without allocating a sample
// per hour. Sparse recordings can span more than a time.Duration can hold.
func HourlyDistribution(times []time.Time, first, last time.Time) Distribution {
	start, end := hourIndex(first), hourIndex(last)
	occupied := map[int64]int64{}
	for _, t := range times {
		if hour := hourIndex(t); hour >= start && hour <= end {
			occupied[hour]++
		}
	}
	n := int(end-start) + 1
	frequencies := map[int64]int{0: n - len(occupied)}
	for _, count := range occupied {
		frequencies[count]++
	}
	values := slices.Sorted(maps.Keys(frequencies))
	rank := func(percent int) *int64 {
		// Split the multiplication to avoid overflow for large populations.
		remaining := n/100*percent + (n%100*percent+99)/100
		for _, value := range values {
			remaining -= frequencies[value]
			if remaining <= 0 {
				return &value
			}
		}
		return nil
	}
	return Distribution{Count: n, P50: rank(50), P90: rank(90), P99: rank(99), Max: rank(100)}
}

func hourIndex(t time.Time) int64 {
	// Truncate before dividing so pre-epoch partial hours round down too.
	return t.Truncate(time.Hour).Unix() / 3600
}
