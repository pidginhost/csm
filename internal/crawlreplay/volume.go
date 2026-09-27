package crawlreplay

import (
	"cmp"
	"math"
	"slices"
)

// Quantiles are nearest-rank summary statistics of a sample.
type Quantiles struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50"`
	P99 float64 `json:"p99"`
	Max float64 `json:"max"`
}

// SummarizeCounts computes nearest-rank quantiles of a histogram that maps
// each integer value to how often it occurred.
func SummarizeCounts(hist map[int64]int64) Quantiles {
	values := make([]int64, 0, len(hist))
	var n int64
	for v, c := range hist {
		if c > 0 {
			values = append(values, v)
			n += c
		}
	}
	if n == 0 {
		return Quantiles{}
	}
	slices.Sort(values)
	rank := func(q float64) float64 {
		target := max(1, int64(math.Ceil(q*float64(n))))
		var seen int64
		for _, v := range values {
			if seen += hist[v]; seen >= target {
				return float64(v)
			}
		}
		return float64(values[len(values)-1])
	}
	return Quantiles{N: int(n), P50: rank(0.50), P99: rank(0.99), Max: float64(values[len(values)-1])}
}

// Summarize computes nearest-rank quantiles; an empty sample is all zero.
func Summarize(sample []float64) Quantiles {
	if len(sample) == 0 {
		return Quantiles{}
	}
	s := slices.Clone(sample)
	slices.Sort(s)
	rank := func(q float64) float64 { return s[max(0, int(math.Ceil(q*float64(len(s))))-1)] }
	return Quantiles{N: len(s), P50: rank(0.50), P99: rank(0.99), Max: s[len(s)-1]}
}

// HostVolume summarizes logged lines and bytes per minute over every
// minute from the earliest to the latest volume row; a minute no site
// logged counts as zero.
type HostVolume struct {
	LinesPerMinute     Quantiles `json:"lines_per_minute"`
	BytesPerMinute     Quantiles `json:"bytes_per_minute"`
	SiteLinesPerMinute Quantiles `json:"site_lines_per_minute"` // site-minutes with lines
}

// SummarizeVolume aggregates volume rows across sites.
func SummarizeVolume(rows []Volume) HostVolume {
	if len(rows) == 0 {
		return HostVolume{}
	}
	lines, bytes := map[int64]float64{}, map[int64]float64{}
	first, last := rows[0].Minute, rows[0].Minute
	site := make([]float64, 0, len(rows))
	for _, v := range rows {
		lines[v.Minute] += float64(v.Lines)
		bytes[v.Minute] += float64(v.Bytes)
		site = append(site, float64(v.Lines))
		first, last = min(first, v.Minute), max(last, v.Minute)
	}
	var l, b []float64
	for m := first; m <= last; m++ {
		l = append(l, lines[m])
		b = append(b, bytes[m])
	}
	return HostVolume{LinesPerMinute: Summarize(l), BytesPerMinute: Summarize(b), SiteLinesPerMinute: Summarize(site)}
}

// LongestSilence returns the longest run of minutes in span with no logged
// line, given the sorted minutes that have volume rows. A long silence in a
// site's coverage may be missing log data rather than no traffic; the
// ledger reviews it before any baseline trains on it.
func LongestSilence(logged []int64, span Span) int64 {
	var longest int64
	next := span.From
	for _, m := range logged {
		if m < span.From || m > span.To {
			continue
		}
		longest = max(longest, m-next)
		next = m + 1
	}
	return max(longest, span.To+1-next)
}

// SiteShape is one site's lateness and key churn, the inputs for choosing
// the lateness watermark and the K1/K2/S detail bounds.
type SiteShape struct {
	// Lateness counts records by how many seconds their time trails the
	// latest time already logged in the same file, in logged order.
	Lateness map[int64]int64
	// WindowKeys holds, per level, the distinct keys with traffic in each
	// W-minute window ending at a covered minute.
	WindowKeys map[uint8][]float64
	// WindowBindings holds the distinct bindings in each site-level window.
	WindowBindings []float64
	// NewKeys holds, per level, the keys first seen in each covered hour.
	NewKeys map[uint8][]float64
}

// ShapeSite measures one site's records over its coverage.
func ShapeSite(site Site, w int) SiteShape {
	shape := SiteShape{Lateness: map[int64]int64{}, WindowKeys: map[uint8][]float64{}, NewKeys: map[uint8][]float64{}}
	ordered := slices.Clone(site.Records)
	slices.SortStableFunc(ordered, func(a, b Record) int {
		return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.Seq, b.Seq))
	})
	latest := map[int]int64{}
	byMinute := map[int64][]Record{}
	for _, r := range ordered {
		if top, ok := latest[r.File]; ok && top > r.T {
			shape.Lateness[top-r.T]++
		} else {
			latest[r.File] = r.T
			shape.Lateness[0]++
		}
		if r.Class != ClassOther && !r.Infra {
			byMinute[r.T/60] = append(byMinute[r.T/60], r)
		}
	}
	firstSeen := map[KeyID]bool{}
	for _, span := range site.Coverage {
		keyCounts := map[KeyID]int{}
		bindCounts := map[string]int{}
		perHour := map[uint8]float64{}
		for m := span.From; m <= span.To; m++ {
			for _, r := range byMinute[m] {
				for _, id := range keysOf(&r) {
					keyCounts[id]++
					if !firstSeen[id] {
						firstSeen[id] = true
						perHour[id.Level]++
					}
				}
				if r.Binding != "" {
					bindCounts[r.Binding]++
				}
			}
			if old := m - int64(w); old >= span.From {
				for _, r := range byMinute[old] {
					for _, id := range keysOf(&r) {
						if keyCounts[id]--; keyCounts[id] == 0 {
							delete(keyCounts, id)
						}
					}
					if r.Binding != "" {
						if bindCounts[r.Binding]--; bindCounts[r.Binding] == 0 {
							delete(bindCounts, r.Binding)
						}
					}
				}
			}
			if m-span.From+1 >= int64(w) {
				levels := map[uint8]float64{}
				for id := range keyCounts {
					levels[id.Level]++
				}
				for level := uint8(1); level <= 3; level++ {
					shape.WindowKeys[level] = append(shape.WindowKeys[level], levels[level])
				}
				shape.WindowBindings = append(shape.WindowBindings, float64(len(bindCounts)))
			}
			if (m+1)%60 == 0 || m == span.To {
				for level := uint8(1); level <= 3; level++ {
					shape.NewKeys[level] = append(shape.NewKeys[level], perHour[level])
				}
				perHour = map[uint8]float64{}
			}
		}
	}
	return shape
}

// Footprint estimates the retained bytes of one key's detector state: the
// hour-of-week profile plus W minutes of summaries with m counters and h
// hashes. It is a sizing aid for K1, K2 and S, not a measurement of
// production code, which plan 1.3 must measure against this estimate.
func Footprint(p Params, s SketchParams) int64 {
	const bindingBytes = 1 + 8 // family byte and the IPv6 /64, the larger form
	profile := int64(168 * (8 + 8))
	perMinute := int64(s.M)*(bindingBytes+8+8) + int64(s.H)*8 + 8
	return profile + int64(p.W)*perMinute
}
