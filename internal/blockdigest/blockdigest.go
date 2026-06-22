// Package blockdigest batches CSM auto-block events into a per-country
// roll-up so operators learn when IPs from their customers' countries get
// blocked. It is deliberately free of config/geoip/alert/daemon imports:
// the daemon injects a country lookup and email/webhook sinks, which keeps
// the logic unit-testable without the linux build tag.
package blockdigest

import (
	"strings"
	"sync"
	"time"
)

type Bucket string

const (
	BucketCustomer Bucket = "customer"
	BucketAttacker Bucket = "attacker"
)

// Record is one deduplicated auto-block observation in the current window.
type Record struct {
	TS      time.Time
	IP      string
	Country string
	Reason  string
	Bucket  Bucket
}

// Digest is the rolled-up view drained at each interval.
type Digest struct {
	Window        time.Duration
	Countries     []string
	Total         int
	CustomerCount int
	AttackerCount int
	ByCountry     map[string]int
	ByReason      map[string]int
	Records       []Record
}

// Options is the fully-resolved collector configuration. The daemon resolves
// countries, interval, channel sinks, and lookups before constructing.
type Options struct {
	Countries   []string // effective watch set, upper-cased; empty means all
	SendOn      string   // any | customer
	Interval    time.Duration
	Live        bool
	MinBlock    int
	Host        string
	Version     string
	CountryOf   func(ip string) string
	Now         func() time.Time
	EmailSink   func(subject, body string) error
	WebhookSink func(p WebhookPayload) error
}

// Collector accumulates observations and drains them into digests.
type Collector struct {
	opts Options

	mu             sync.Mutex
	records        []Record
	lastLive       map[string]time.Time
	lastLivePruned time.Time
}

const maxBuffered = 5000

func New(opts Options) *Collector {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.CountryOf == nil {
		opts.CountryOf = func(string) string { return "" }
	}
	opts.Countries = append([]string(nil), opts.Countries...)
	return &Collector{opts: opts, lastLive: make(map[string]time.Time)}
}

func (c *Collector) countriesSnapshot() []string {
	return append([]string(nil), c.opts.Countries...)
}

// ResolveCountries returns the effective upper-cased watch set: configured
// wins, else trusted_countries, else empty (meaning all countries).
func ResolveCountries(configured, trusted []string) []string {
	if out := normalizeCountries(configured); len(out) > 0 {
		return out
	}
	return normalizeCountries(trusted)
}

func normalizeCountries(src []string) []string {
	out := make([]string, 0, len(src))
	for _, c := range src {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// classifyBucket maps an auto-block reason to a bucket. Attacker keywords are
// checked first; anything else (including unrecognized reasons) is treated as
// likely-customer so a possible false positive is never hidden from review.
func classifyBucket(reason string) Bucket {
	r := strings.ToLower(reason)
	attacker := []string{
		"rule escalation", "brute", "mail auth", "web_attack", "web attack",
		"account compromise", "command-and-control", "user-agent spoof",
		"ua spoof", "bad asn", "credential stuffing", "credential-stuffing",
		"credential abuse", "credential-abuse", "credentials compromised",
	}
	for _, k := range attacker {
		if strings.Contains(r, k) {
			return BucketAttacker
		}
	}
	if containsWord(r, "c2") {
		return BucketAttacker
	}
	return BucketCustomer
}

func containsWord(s, word string) bool {
	for start := 0; start < len(s); {
		idx := strings.Index(s[start:], word)
		if idx < 0 {
			return false
		}
		idx += start
		after := idx + len(word)
		if (idx == 0 || !isWordByte(s[idx-1])) && (after == len(s) || !isWordByte(s[after])) {
			return true
		}
		start = after
	}
	return false
}

func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_'
}

func (c *Collector) watched(country string) bool {
	if len(c.opts.Countries) == 0 {
		return true
	}
	if country == "" {
		return false
	}
	for _, w := range c.opts.Countries {
		if strings.EqualFold(country, w) {
			return true
		}
	}
	return false
}

// Observe records one auto-block. It geo-classifies, filters to the watch set,
// buckets the reason, and (when Live) may fire an immediate alert.
func (c *Collector) Observe(ip, reason string, ts time.Time) {
	country := c.opts.CountryOf(ip)
	if !c.watched(country) {
		return
	}
	bucket := classifyBucket(reason)
	rec := Record{TS: ts, IP: ip, Country: country, Reason: reason, Bucket: bucket}

	c.mu.Lock()
	if len(c.records) < maxBuffered {
		c.records = append(c.records, rec)
	} else {
		// drop-oldest: the digest only needs the interval's worth.
		c.records = append(c.records[1:], rec)
	}
	c.mu.Unlock()

	if c.opts.Live {
		c.maybeLive(rec)
	}
}

// Drain pulls the current window into a Digest (deduped by IP, customer first)
// and clears the buffer.
func (c *Collector) Drain() Digest {
	c.mu.Lock()
	recs := c.records
	c.records = nil
	c.mu.Unlock()

	d := Digest{
		Window:    c.opts.Interval,
		Countries: c.countriesSnapshot(),
		ByCountry: map[string]int{},
		ByReason:  map[string]int{},
	}
	selected := make(map[string]Record, len(recs))
	order := make([]string, 0, len(recs))
	for _, r := range recs {
		existing, ok := selected[r.IP]
		if !ok {
			selected[r.IP] = r
			order = append(order, r.IP)
			continue
		}
		if existing.Bucket != BucketCustomer && r.Bucket == BucketCustomer {
			selected[r.IP] = r
		}
	}

	var customer, attacker []Record
	for _, ip := range order {
		r := selected[ip]
		d.Total++
		d.ByCountry[r.Country]++
		d.ByReason[reasonKey(r.Reason)]++
		if r.Bucket == BucketCustomer {
			d.CustomerCount++
			customer = append(customer, r)
		} else {
			d.AttackerCount++
			attacker = append(attacker, r)
		}
	}
	d.Records = make([]Record, 0, len(customer)+len(attacker))
	d.Records = append(d.Records, customer...)
	d.Records = append(d.Records, attacker...)
	return d
}

// reasonKey collapses a reason to its leading phrase (before the first ':')
// so per-reason counts group "ModSecurity escalation: 5+ ..." together.
func reasonKey(reason string) string {
	if i := strings.IndexByte(reason, ':'); i > 0 {
		return strings.TrimSpace(reason[:i])
	}
	return strings.TrimSpace(reason)
}

// maybeLive fires an immediate single-record alert for a qualifying block.
// It honors send_on (customer mode only alerts on customer-risk blocks) and
// dedups per IP within one Interval so a re-blocked IP cannot spam.
func (c *Collector) maybeLive(rec Record) {
	if c.opts.SendOn == "customer" && rec.Bucket != BucketCustomer {
		return
	}
	now := c.opts.Now()
	c.mu.Lock()
	c.pruneLastLiveLocked(now)
	if last, ok := c.lastLive[rec.IP]; ok && c.opts.Interval > 0 && now.Sub(last) < c.opts.Interval {
		c.mu.Unlock()
		return
	}
	c.lastLive[rec.IP] = now
	c.mu.Unlock()

	d := Digest{
		Window: c.opts.Interval, Countries: c.countriesSnapshot(),
		Total: 1, ByCountry: map[string]int{rec.Country: 1},
		ByReason: map[string]int{reasonKey(rec.Reason): 1},
		Records:  []Record{rec},
	}
	if rec.Bucket == BucketCustomer {
		d.CustomerCount = 1
	} else {
		d.AttackerCount = 1
	}
	c.dispatch("block_live", d)
}

func (c *Collector) pruneLastLiveLocked(now time.Time) {
	interval := c.opts.Interval
	if interval <= 0 {
		clear(c.lastLive)
		c.lastLivePruned = now
		return
	}
	if !c.lastLivePruned.IsZero() && now.Sub(c.lastLivePruned) < interval {
		return
	}
	cutoff := now.Add(-interval)
	for ip, last := range c.lastLive {
		if !last.After(cutoff) {
			delete(c.lastLive, ip)
		}
	}
	c.lastLivePruned = now
}

// tick drains the window and sends a digest when gating allows.
func (c *Collector) tick() {
	d := c.Drain()
	if !c.shouldSend(d) {
		return
	}
	c.dispatch("block_digest", d)
}

// Flush sends one final digest regardless of cadence (shutdown path).
func (c *Collector) Flush() { c.tick() }

// Run loops draining on each tick and drains a final digest on stop.
func (c *Collector) Run(stop <-chan struct{}, tick <-chan time.Time) {
	for {
		select {
		case <-stop:
			c.Flush()
			return
		case _, ok := <-tick:
			if !ok {
				c.Flush()
				return
			}
			c.tick()
		}
	}
}

// dispatch delivers a digest through whichever sinks are configured. Sink
// errors are swallowed deliberately: alert delivery is best-effort and must
// never block the collector or the auto-block path. A sink that needs to
// surface failures logs inside its own closure on the daemon side.
func (c *Collector) dispatch(event string, d Digest) {
	if c.opts.EmailSink != nil {
		_ = c.opts.EmailSink(c.renderSubject(d), c.renderBody(d))
	}
	if c.opts.WebhookSink != nil {
		_ = c.opts.WebhookSink(c.buildPayload(event, d))
	}
}
