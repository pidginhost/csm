package blockdigest

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
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

// One pending window bounds retry state during a prolonged outage. Findings
// arriving during delivery belong to the active window, not its retries.
type pendingSummary struct {
	Summary
	Until       time.Time `json:"until"`
	EmailDone   bool      `json:"email_done"`
	WebhookDone bool      `json:"webhook_done"`
}

func (p *pendingSummary) done(channel string) bool {
	if channel == "email" {
		return p.EmailDone
	}
	return p.WebhookDone
}

func (p *pendingSummary) markDone(channel string) {
	if channel == "email" {
		p.EmailDone = true
	} else {
		p.WebhookDone = true
	}
}

// summaryRetry is the backoff of one failing destination of the pending
// window, or of failing saves. It lives in memory: a restart retries at once.
// ticket keeps a failed destination one waiting notification between
// attempts, so health shows the outage.
type summaryRetry struct {
	delay  time.Duration
	next   time.Time
	ticket queuehealth.Ticket
	// tried means an attempt in this process already accounted for the
	// destination, as a loss or an uncertain delivery, so later failures and
	// a drop of the window do not count it again.
	tried bool
}

// fail doubles the wait from one minute up to one hour and reports whether
// to warn: on the first failure and when the wait reaches the hour.
func (r *summaryRetry) fail(now time.Time) bool {
	previous := r.delay
	r.delay = min(max(summaryRetryFirst, 2*previous), summaryRetryMax)
	r.next = now.Add(r.delay)
	return previous == 0 || previous < summaryRetryMax && r.delay == summaryRetryMax
}

var summaryChannels = [...]string{"email", "webhook"}

const (
	summaryRetryFirst = time.Minute
	summaryRetryMax   = time.Hour
)

type summaryState struct {
	Summary
	Pending  *pendingSummary `json:"pending,omitempty"`
	LastSent time.Time       `json:"last_sent,omitempty"`
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

// Flush checkpoints the active and pending windows without delivering. The
// daemon calls it again after its final alert drain, once all producers stop.
func (c *Collector) Flush() {
	c.summaryMu.Lock()
	defer c.summaryMu.Unlock()
	c.fold()
	c.save()
}

// save is called with summaryMu held; no injected callback runs under mu.
// A failure warns like a failing destination: on the first one, then when
// the wait between warnings reaches an hour.
func (c *Collector) save() {
	if c.opts.SaveSummary == nil {
		return
	}
	c.mu.Lock()
	b, err := json.Marshal(summaryState{Summary: c.sum, Pending: c.pending, LastSent: c.lastSent})
	c.mu.Unlock()
	if err == nil {
		err = c.opts.SaveSummary(b)
	}
	if err == nil {
		c.saveRetry = summaryRetry{}
		return
	}
	if now := c.opts.Now(); !now.Before(c.saveRetry.next) && c.saveRetry.fail(now) {
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
	c.summaryMu.Lock()
	defer c.summaryMu.Unlock()
	if c.opts.LoadSummary == nil {
		return
	}
	b, err := c.opts.LoadSummary()
	if err == nil && len(b) == 0 {
		return
	}
	var s summaryState
	if err == nil {
		err = json.Unmarshal(b, &s)
	}
	if err == nil && (s.Since.IsZero() || s.Due.IsZero() || s.Pending != nil && (s.Pending.Since.IsZero() || s.Pending.Until.IsZero())) {
		err = errors.New("saved daily summary has no window start or send time")
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
	c.sum = s.Summary
	c.pending = s.Pending
	c.lastSent = s.LastSent
	c.mu.Unlock()
}

func (c *Collector) untilDue() time.Duration {
	c.summaryMu.Lock()
	defer c.summaryMu.Unlock()
	if c.pending != nil {
		return time.Minute
	}
	c.mu.Lock()
	due := c.sum.Due
	c.mu.Unlock()
	// Go timers use elapsed time. Recheck the wall clock and any pending
	// delivery every minute, even when the configured fold interval is long.
	return min(time.Minute, max(time.Second, due.Sub(c.opts.Now())))
}

// SendDue checkpoints a due window before offering it to either sink. Failed
// destinations retain that window and retry with backoff; completed
// destinations are checkpointed separately. A crash after remote acceptance
// but before its checkpoint can still repeat that destination, since
// notification sinks are not transactional. The return value reports a
// delivery attempt, not whether its sinks succeeded.
func (c *Collector) SendDue(now time.Time) bool {
	c.summaryMu.Lock()
	defer c.summaryMu.Unlock()
	c.mu.Lock()
	if now.Before(c.sum.Due) {
		c.sum.clamp(now, c.opts.Location)
		// A correction back across this morning's send must not send the
		// same local date twice, including after a restart.
		if !c.lastSent.IsZero() && c.sum.Due.In(c.opts.Location).Format(time.DateOnly) <= c.lastSent.In(c.opts.Location).Format(time.DateOnly) {
			c.sum.Due = nextSummaryDue(c.lastSent, c.opts.Location)
		}
		c.mu.Unlock()
		if c.pending == nil {
			return false
		}
		c.settleDisabled()
		if !c.retryDue(now) {
			return false
		}
	} else {
		c.mu.Unlock()
		// One pending window bounds retries: the next one replaces it, so a
		// failing destination never holds back the others.
		if c.pending != nil {
			c.settleDisabled()
		}
		c.dropPending()
		c.fold()
		c.mu.Lock()
		c.pending = &pendingSummary{Summary: c.sum, Until: now}
		c.sum = newSummary(now, nextSummaryDue(now, c.opts.Location))
		c.mu.Unlock()
		// Sent for this date from now on, even while a destination still
		// retries, so a clock stepped back cannot send the date again.
		c.lastSent = now
	}
	// A failed save does not hold the summary back; a crash repeats it.
	c.save()

	pending := c.pending
	waiting := func(channel string) bool { return now.Before(c.retries[channel].next) }
	// A destination that failed before keeps its waiting notification.
	held := make(map[string]queuehealth.Ticket, len(summaryChannels))
	for channel, r := range c.retries {
		if r.ticket != (queuehealth.Ticket{}) && !waiting(channel) {
			held[channel] = r.ticket
			r.ticket = queuehealth.Ticket{}
			c.retries[channel] = r
		}
	}
	plan := c.beginDelivery(func(channel string) bool {
		if pending.done(channel) || waiting(channel) {
			return false
		}
		return c.opts.DeliveryEnabled == nil || c.opts.DeliveryEnabled("daily_summary", channel)
	}, held)
	defer plan.finish()
	if c.retries == nil {
		c.retries = make(map[string]summaryRetry, len(summaryChannels))
	}
	for _, channel := range summaryChannels {
		if job := plan.job(channel); job != nil && job.tracked {
			r := c.retries[channel]
			job.repeat = r.tried
			r.tried = true
			c.retries[channel] = r
		}
	}
	view := c.summaryView(pending.Summary)
	body := c.summaryBody(view, pending.Until)
	c.deliver(plan, c.summarySubject(view), body, c.summaryPayload(view, body), func(channel string, attempted bool, err error) {
		switch {
		case pending.done(channel), !attempted && waiting(channel):
		case err == nil:
			pending.markDone(channel)
			c.save()
		default:
			c.retryLater(channel, now, err)
			// Hold the failed notification as waiting for the next attempt.
			// A logger that does not return leaves it to plan.finish.
			job := plan.job(channel)
			job.ticket.Requeue(time.Now())
			job.tracked = false
			r := c.retries[channel]
			r.ticket = job.ticket
			// A destination enabled after the attempt began was not marked
			// tried with the others; its loss is counted now.
			r.tried = true
			c.retries[channel] = r
		}
	})
	if !pending.EmailDone || !pending.WebhookDone {
		return true
	}
	c.pending = nil
	c.retries = nil
	c.save()
	return true
}

// retryDue reports whether the pending window has a destination to try now,
// or none left, as after a crash between the last success and the rollover.
func (c *Collector) retryDue(now time.Time) bool {
	for _, channel := range summaryChannels {
		if !c.pending.done(channel) && !now.Before(c.retries[channel].next) {
			return true
		}
	}
	return c.pending.EmailDone && c.pending.WebhookDone
}

// retryLater schedules a failing destination's next attempt. Only the first
// failure and reaching the hourly cap are reported, so an outage of hours
// logs twice, not every minute.
func (c *Collector) retryLater(channel string, now time.Time, err error) {
	r := c.retries[channel]
	warn := r.fail(now)
	c.retries[channel] = r
	if warn {
		c.reportSinkError(channel, err)
	}
}

// settleDisabled marks done the unfinished destinations the delivery policy
// now switches off, as an attempt would, without waiting out their backoff,
// and releases their waiting notification.
func (c *Collector) settleDisabled() {
	settled := false
	for _, channel := range summaryChannels {
		if c.pending.done(channel) {
			continue
		}
		if c.queues.sinks[channel] != nil && (c.opts.DeliveryEnabled == nil || c.opts.DeliveryEnabled("daily_summary", channel)) {
			continue
		}
		c.retries[channel].ticket.Finish(time.Now())
		delete(c.retries, channel)
		c.pending.markDone(channel)
		settled = true
	}
	if settled {
		c.save()
	}
}

// dropPending gives up the pending window when the next one is due. Its
// unfinished destinations were accounted for on their first attempt; one not
// attempted in this process, as after a restart, counts its loss here.
func (c *Collector) dropPending() {
	p := c.pending
	if p == nil {
		return
	}
	var unfinished []string
	for _, channel := range summaryChannels {
		if p.done(channel) {
			continue
		}
		unfinished = append(unfinished, channel)
		r := c.retries[channel]
		r.ticket.Finish(time.Now())
		if q := c.queues.sinks[channel]; q != nil && !r.tried && (c.opts.DeliveryEnabled == nil || c.opts.DeliveryEnabled("daily_summary", channel)) {
			q.tracker.Lose(time.Now(), 1)
		}
	}
	c.pending = nil
	c.retries = nil
	if len(unfinished) > 0 {
		c.reportSinkError(strings.Join(unfinished, ","), fmt.Errorf("daily summary from %s not delivered before the next one was due; dropped", p.Since.In(c.opts.Location).Format(time.DateOnly)))
	}
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
