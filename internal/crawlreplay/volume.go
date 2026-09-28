package crawlreplay

import (
	"cmp"
	"maps"
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
// logged counts as zero. SummarizeVolumePeriods restricts that extent to
// the supplied recording periods.
type HostVolume struct {
	LinesPerMinute     Quantiles `json:"lines_per_minute"`
	BytesPerMinute     Quantiles `json:"bytes_per_minute"`
	SiteLinesPerMinute Quantiles `json:"site_lines_per_minute"` // site-minutes with lines
}

// SummarizeVolume aggregates volume rows across sites.
func SummarizeVolume(rows []Volume) HostVolume {
	return SummarizeVolumePeriods(rows, nil)
}

// SummarizeVolumePeriods excludes gaps between recording periods. Periods
// must be chronological and disjoint and contain every row. A nil list
// uses the full observed extent, as SummarizeVolume does.
func SummarizeVolumePeriods(rows []Volume, periods []Span) HostVolume {
	if len(rows) == 0 {
		return HostVolume{}
	}
	lines, bytes := map[int64]float64{}, map[int64]float64{}
	type siteMinute struct {
		site   string
		minute int64
	}
	siteLines := map[siteMinute]float64{}
	first, last := rows[0].Minute, rows[0].Minute
	for _, v := range rows {
		lines[v.Minute] += float64(v.Lines)
		bytes[v.Minute] += float64(v.Bytes)
		siteLines[siteMinute{v.Site, v.Minute}] += float64(v.Lines)
		first, last = min(first, v.Minute), max(last, v.Minute)
	}
	site := make([]float64, 0, len(siteLines))
	for _, n := range siteLines {
		site = append(site, n)
	}
	var l, b []float64
	if periods == nil {
		periods = []Span{{From: first, To: last}}
	}
	for _, period := range periods {
		for m := max(first, period.From); m <= min(last, period.To); m++ {
			l = append(l, lines[m])
			b = append(b, bytes[m])
		}
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
	tracker := NewShapeTracker(w)
	tracker.Add(site)
	return tracker.Report()
}

// ShapeTracker carries one site's diagnostic windows and first-seen keys
// across chronological bundles. Only the current window's records remain
// retained; earlier traffic contributes summary samples and key identities.
type ShapeTracker struct {
	w                       int
	shape                   SiteShape
	firstSeen               map[KeyID]bool
	keyCounts               map[KeyID]int
	bindCounts              map[string]int
	window                  map[int64][]Record
	last, coveredFrom, hour int64
}

// NewShapeTracker starts one site's diagnostics with a positive window.
func NewShapeTracker(w int) *ShapeTracker {
	return &ShapeTracker{w: w, hour: -1, firstSeen: map[KeyID]bool{},
		shape: SiteShape{Lateness: map[int64]int64{}, WindowKeys: map[uint8][]float64{}, NewKeys: map[uint8][]float64{}}}
}

// Add measures a validated bundle segment after every minute already added.
// File numbers belong to this bundle; lateness never joins distinct copies.
func (s *ShapeTracker) Add(site Site) {
	ordered := slices.Clone(site.Records)
	slices.SortStableFunc(ordered, func(a, b Record) int {
		return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.Seq, b.Seq))
	})
	latest := map[int]int64{}
	byMinute := map[int64][]Record{}
	for _, r := range ordered {
		if top, ok := latest[r.File]; ok && top > r.T {
			s.shape.Lateness[top-r.T]++
		} else {
			latest[r.File] = r.T
			s.shape.Lateness[0]++
		}
		if r.Class != ClassOther && !r.Infra {
			byMinute[r.T/60] = append(byMinute[r.T/60], r)
		}
	}
	for _, span := range site.Coverage {
		if s.last == 0 || span.From-1 != s.last {
			s.coveredFrom = span.From
			s.keyCounts = map[KeyID]int{}
			s.bindCounts = map[string]int{}
			s.window = map[int64][]Record{}
		}
		for m := span.From; m <= span.To; m++ {
			s.minute(m, byMinute[m])
		}
	}
}

func (s *ShapeTracker) minute(m int64, records []Record) {
	if m/60 != s.hour {
		s.hour = m / 60
		for level := uint8(1); level <= 3; level++ {
			s.shape.NewKeys[level] = append(s.shape.NewKeys[level], 0)
		}
	}
	for _, r := range records {
		for _, id := range keysOf(&r) {
			s.keyCounts[id]++
			if !s.firstSeen[id] {
				s.firstSeen[id] = true
				counts := s.shape.NewKeys[id.Level]
				counts[len(counts)-1]++
			}
		}
		if r.Binding != "" {
			s.bindCounts[r.Binding]++
		}
	}
	if len(records) > 0 {
		s.window[m] = records
	}
	old := m - int64(s.w)
	for _, r := range s.window[old] {
		for _, id := range keysOf(&r) {
			if s.keyCounts[id]--; s.keyCounts[id] == 0 {
				delete(s.keyCounts, id)
			}
		}
		if r.Binding != "" {
			if s.bindCounts[r.Binding]--; s.bindCounts[r.Binding] == 0 {
				delete(s.bindCounts, r.Binding)
			}
		}
	}
	delete(s.window, old)
	if m-s.coveredFrom+1 >= int64(s.w) {
		levels := map[uint8]float64{}
		for id := range s.keyCounts {
			levels[id.Level]++
		}
		for level := uint8(1); level <= 3; level++ {
			s.shape.WindowKeys[level] = append(s.shape.WindowKeys[level], levels[level])
		}
		s.shape.WindowBindings = append(s.shape.WindowBindings, float64(len(s.bindCounts)))
	}
	s.last = m
}

// Report returns diagnostics independent of later additions to the tracker.
func (s *ShapeTracker) Report() SiteShape {
	out := SiteShape{Lateness: maps.Clone(s.shape.Lateness), WindowBindings: slices.Clone(s.shape.WindowBindings),
		WindowKeys: map[uint8][]float64{}, NewKeys: map[uint8][]float64{}}
	for level, values := range s.shape.WindowKeys {
		out.WindowKeys[level] = slices.Clone(values)
	}
	for level, values := range s.shape.NewKeys {
		out.NewKeys[level] = slices.Clone(values)
	}
	return out
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
