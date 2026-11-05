package blockdigest

import (
	"cmp"
	"encoding/json"
	"slices"
	"time"
)

const (
	// summaryHour is the local hour the daily summary is sent at.
	summaryHour = 8
	// maxSummarySources caps the tracked source addresses. The top list is
	// a space-saving count, so a flood of one-off addresses cannot push a
	// heavy source out.
	maxSummarySources = 1000
	summaryTopSources = 10
	// maxSummaryKeys caps each count map; later keys count under
	// overflowKey. Check names, kinds and countries come from CSM itself,
	// so the cap is a backstop, not a limit real traffic reaches.
	maxSummaryKeys = 512
	overflowKey    = "other"
)

// Handled is one summary-class finding as the daemon maps it. BlockReason is
// set for an applied auto_block only.
type Handled struct {
	Check, Severity, IP, BlockReason string
	Muted                            bool
}

// SourceCount is one source address and its summary findings. Country is
// filled only in a sent summary's top list.
type SourceCount struct {
	IP      string `json:"ip"`
	Count   int    `json:"count"`
	Country string `json:"country,omitempty"`
}

// WatchedBlocks are the watched-country blocks folded into the summary.
type WatchedBlocks struct {
	Total      int            `json:"total"`
	ByCountry  map[string]int `json:"by_country"`
	ByCategory map[string]int `json:"by_category"`
}

// Summary is the persisted daily summary window.
type Summary struct {
	Since      time.Time                 `json:"since"`
	Due        time.Time                 `json:"due"`
	Checks     map[string]map[string]int `json:"checks"` // check, then severity
	Blocks     int                       `json:"blocks"`
	BlockKinds map[string]int            `json:"block_kinds"` // by categoryOf
	Muted      int                       `json:"muted"`
	Sources    []SourceCount             `json:"sources"`
	Watched    WatchedBlocks             `json:"watched"`
}

func newSummary(since, due time.Time) Summary {
	s := Summary{Since: since, Due: due}
	s.init()
	return s
}

func (s *Summary) init() {
	if s.Checks == nil {
		s.Checks = make(map[string]map[string]int)
	}
	if s.BlockKinds == nil {
		s.BlockKinds = make(map[string]int)
	}
	if s.Watched.ByCountry == nil {
		s.Watched.ByCountry = make(map[string]int)
	}
	if s.Watched.ByCategory == nil {
		s.Watched.ByCategory = make(map[string]int)
	}
}

// nextSummaryDue returns the first summaryHour:00 in loc strictly after now.
// It builds wall-clock dates instead of adding 24h, so the send time stays
// at 08:00 on daylight saving days.
func nextSummaryDue(now time.Time, loc *time.Location) time.Time {
	t := now.In(loc)
	due := time.Date(t.Year(), t.Month(), t.Day(), summaryHour, 0, 0, 0, loc)
	if !due.After(now) {
		due = time.Date(t.Year(), t.Month(), t.Day()+1, summaryHour, 0, 0, 0, loc)
	}
	return due
}

func boundedKey[V any](m map[string]V, key string) string {
	if _, ok := m[key]; ok || len(m) < maxSummaryKeys {
		return key
	}
	return overflowKey
}

func addCounts(dst, src map[string]int) {
	for k, n := range src {
		dst[boundedKey(dst, k)] += n
	}
}

func (s *Summary) note(h Handled) {
	check := boundedKey(s.Checks, h.Check)
	if s.Checks[check] == nil {
		s.Checks[check] = make(map[string]int)
	}
	s.Checks[check][h.Severity]++
	if h.Muted {
		s.Muted++
	}
	if h.BlockReason != "" {
		s.Blocks++
		s.BlockKinds[boundedKey(s.BlockKinds, categoryOf(h.BlockReason))]++
	}
	if h.IP != "" {
		s.addSource(h.IP, 1)
	}
}

// addSource counts n findings for ip. When the list is full, the address
// with the lowest count is replaced and the newcomer inherits that count, so
// a count can overstate a newcomer but never understates a heavy source.
// ponytail: linear scan of the capped list; a heap if inserts get hot.
func (s *Summary) addSource(ip string, n int) {
	lowest := 0
	for i := range s.Sources {
		if s.Sources[i].IP == ip {
			s.Sources[i].Count += n
			return
		}
		if s.Sources[i].Count < s.Sources[lowest].Count {
			lowest = i
		}
	}
	if len(s.Sources) < maxSummarySources {
		s.Sources = append(s.Sources, SourceCount{IP: ip, Count: n})
		return
	}
	s.Sources[lowest] = SourceCount{IP: ip, Count: s.Sources[lowest].Count + n}
}

func (w *WatchedBlocks) add(total int, byCountry, byCategory map[string]int) {
	w.Total += total
	addCounts(w.ByCountry, byCountry)
	addCounts(w.ByCategory, byCategory)
}

// merge adds the counts of o, noted before the saved window was loaded.
func (s *Summary) merge(o Summary) {
	for check, bySeverity := range o.Checks {
		key := boundedKey(s.Checks, check)
		if s.Checks[key] == nil {
			s.Checks[key] = make(map[string]int)
		}
		addCounts(s.Checks[key], bySeverity)
	}
	s.Blocks += o.Blocks
	addCounts(s.BlockKinds, o.BlockKinds)
	s.Muted += o.Muted
	for _, src := range o.Sources {
		s.addSource(src.IP, src.Count)
	}
	s.Watched.add(o.Watched.Total, o.Watched.ByCountry, o.Watched.ByCategory)
}

func (s *Summary) total() int {
	n := 0
	for _, bySeverity := range s.Checks {
		for _, c := range bySeverity {
			n += c
		}
	}
	return n
}

func (s *Summary) checkTotal(check string) int {
	n := 0
	for _, c := range s.Checks[check] {
		n += c
	}
	return n
}

func sortSources(src []SourceCount) {
	slices.SortFunc(src, func(a, b SourceCount) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.IP, b.IP))
	})
}

// NoteHandled counts summary-class findings into the current window.
func (c *Collector) NoteHandled(batch []Handled) {
	if len(batch) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, h := range batch {
		c.sum.note(h)
	}
}

// fold moves the watched-country buffer into the summary window.
func (c *Collector) fold() {
	d, batch := c.drain()
	c.mu.Lock()
	c.sum.Watched.add(d.Total, d.ByCountry, d.ByCategory)
	c.mu.Unlock()
	batch.finish(true)
}

func (c *Collector) save() {
	if c.opts.SaveSummary == nil {
		return
	}
	c.mu.Lock()
	b, err := json.Marshal(c.sum)
	c.mu.Unlock()
	if err == nil {
		err = c.opts.SaveSummary(b)
	}
	if err != nil {
		c.reportSinkError("summary", err)
	}
}

// clamp pulls a send time past the next one, or a start in the future, back
// to now: either means the clock went back, and the summary must not be held
// for days.
func (s *Summary) clamp(now time.Time, loc *time.Location) {
	if next := nextSummaryDue(now, loc); s.Due.After(next) {
		s.Due = next
	}
	if s.Since.After(now) {
		s.Since = now
	}
}

// load replaces the fresh window with the saved one and adds what was noted
// since New. Run's first SendDue then clamps a send time the clock left behind.
func (c *Collector) load() {
	if c.opts.LoadSummary == nil {
		return
	}
	b, err := c.opts.LoadSummary()
	if err == nil && len(b) == 0 {
		return
	}
	var s Summary
	if err == nil {
		err = json.Unmarshal(b, &s)
	}
	if err != nil {
		c.reportSinkError("summary", err)
		return
	}
	s.init()
	if len(s.Sources) > maxSummarySources {
		sortSources(s.Sources)
		s.Sources = s.Sources[:maxSummarySources]
	}
	c.mu.Lock()
	s.merge(c.sum)
	c.sum = s
	c.mu.Unlock()
}

func (c *Collector) untilDue() time.Duration {
	c.mu.Lock()
	due := c.sum.Due
	c.mu.Unlock()
	return due.Sub(c.opts.Now())
}

// SendDue sends the summary when now has reached its send time, then starts
// the next window. The new window is saved only after the sinks return, so a
// crash during delivery sends that summary again at the next start.
func (c *Collector) SendDue(now time.Time) bool {
	c.fold()
	c.mu.Lock()
	if now.Before(c.sum.Due) {
		c.sum.clamp(now, c.opts.Location)
		c.mu.Unlock()
		return false
	}
	sent := c.sum
	c.sum = newSummary(now, nextSummaryDue(now, c.opts.Location))
	c.mu.Unlock()

	plan := c.beginDelivery()
	defer plan.finish()
	view := c.summaryView(sent)
	body := c.summaryBody(view, now)
	c.deliver(plan, c.summarySubject(view), body, c.summaryPayload(view, body))
	c.save()
	return true
}

// summaryView is the sent form of s: its top sources, with country.
func (c *Collector) summaryView(s Summary) Summary {
	top := append([]SourceCount(nil), s.Sources...)
	sortSources(top)
	if len(top) > summaryTopSources {
		top = top[:summaryTopSources]
	}
	for i := range top {
		top[i].Country = c.opts.CountryOf(top[i].IP)
	}
	s.Sources = top
	return s
}
