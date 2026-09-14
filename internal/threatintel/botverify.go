package threatintel

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type resolver interface {
	LookupAddr(ctx context.Context, ip string) ([]string, error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// verifier owns one resolver + a domain suffix list per bot identity.
// One verifier per bot identity in practice; tests construct directly.
type verifier struct {
	res     resolver
	domains []string // lower-case suffix list, e.g. "googlebot.com"
}

func newVerifier(r resolver, domains []string) *verifier {
	low := make([]string, len(domains))
	for i, d := range domains {
		low[i] = strings.ToLower(d)
	}
	return &verifier{res: r, domains: low}
}

// LogicVersion identifies the current shape of the bot-verifier logic
// (BotDomains suffix list, ClaimedBotFromUA mapping, no-PTR semantics).
// Bump this whenever a change here would invalidate cache entries
// written by an older build -- for example, adding a new domain suffix
// that turns prior negatives into positives, or adding a new UA -> bot
// identity mapping. The daemon calls store.DB.EnsureBotVerifyLogicVersion
// at startup with this value; a mismatch wipes the botverify bucket so
// the next scan re-verifies every IP under the new rules.
const LogicVersion = 5

// ErrUnverifiable signals that the resolver returned no usable PTR for
// the source IP, so the verifier cannot prove or disprove the claimed
// bot identity. Callers treat this as fail-open: do not cache a verdict or
// flag as spoof. Genuine spoof signals -- PTR present but outside the
// bot's domain suffix list, or forward-confirm mismatch -- still return
// (false, nil).
var ErrUnverifiable = errors.New("bot verify: no PTR record for source IP")

// verify performs Google's official PTR + forward-A method. Returns
// (true, nil) on success, (false, nil) on a definitive negative
// (PTR resolves but does not belong to the claimed bot's domain, or
// forward-A fails to round-trip the IP), (false, ErrUnverifiable) when
// the IP has no PTR at all, and (false, err) on context cancellation
// or transient resolver failure. Both error paths cause the async
// worker to skip the verdict write so unverifiable IPs do not get pinned
// as spoof for the TTL window.
func (v *verifier) verify(ctx context.Context, ip net.IP, bot string) (bool, error) {
	names, err := v.res.LookupAddr(ctx, ip.String())
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		if isDNSNotFound(err) {
			return false, ErrUnverifiable
		}
		return false, err
	}
	if len(names) == 0 {
		return false, ErrUnverifiable
	}
	matched := ""
	for _, n := range names {
		ln := strings.ToLower(strings.TrimSuffix(n, "."))
		for _, suf := range v.domains {
			if strings.HasSuffix(ln, "."+suf) || ln == suf {
				matched = ln
				break
			}
		}
		if matched != "" {
			break
		}
	}
	if matched == "" {
		return false, nil
	}
	addrs, err := v.res.LookupIP(ctx, "ip", matched)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		if isDNSNotFound(err) {
			return false, nil
		}
		return false, err
	}
	for _, a := range addrs {
		if a.Equal(ip) {
			return true, nil
		}
	}
	return false, nil
}

func isDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound && !dnsErr.IsTemporary && !dnsErr.IsTimeout
}

// AsyncBotVerifier runs PTR+forward-A verify in a single background
// goroutine, deduplicating in-flight jobs. Result writes through the
// put callback (store.DB.PutBotVerify); reads happen from the scan
// hot path via store.DB.GetBotVerify with no goroutine.
type AsyncBotVerifier struct {
	mu       sync.Mutex
	inflight map[string]time.Time
	attempts map[string]botVerifyAttempt
	ch       chan verifyJob
	v        map[string]*verifier // bot identity -> verifier; guarded by mu
	res      resolver             // retained so SetOperatorEntries can rebuild v
	put      func(net.IP, string, bool, time.Time) error
	// unverifiable holds no-PTR results. A missing PTR rarely changes between
	// scans, so repeat claims wait for the record to lapse instead of queuing
	// the same lookup on every scan and crowding out crawlers not yet checked.
	unverifiable UnverifiableRecords
	// unverifiableSwept tracks sweep attempts, including failures, and is
	// owned by the single worker that writes records.
	unverifiableSwept time.Time
	stats             *queuehealth.Tracker
	stop              <-chan struct{}
	closed            bool
}

// Attempt history prevents each unresolved retry from renewing the initial
// grace. It is bounded by queue capacity. New sources can replace the oldest
// completed attempt after its initial cooldown, so repeated failures cannot
// reserve every slot for the full cache TTL. A live job or newly granted grace
// is never evicted; retries cannot slide that reservation indefinitely.
type botVerifyAttempt struct {
	retryAfter  time.Time
	retainUntil time.Time
	expiresAt   time.Time
}

type verifyJob struct {
	IP     net.IP
	Bot    string
	ticket queuehealth.Ticket
}

// BotDomains maps each claimed-bot identity to the DNS suffix list
// used for PTR + forward-A verification. Covers all bots that appear
// frequently in production traffic and have no published static IP
// range (Task 4 handles static-range bots via embedded JSON).
var BotDomains = map[string][]string{
	"googlebot":     {"googlebot.com", "google.com"},
	"bingbot":       {"search.msn.com"},
	"applebot":      {"applebot.apple.com", "apple.com"},
	"duckduckbot":   {"duckduckgo.com"},
	"amazonbot":     {"amazonbot.amazon", "amazon.com", "developer.amazon.com"},
	"gptbot":        {"openai.com"},
	"claudebot":     {"anthropic.com"},
	"perplexitybot": {"perplexity.ai"},
	"facebookbot":   {"fbsv.net", "tfbnw.net", "facebook.com"},
	"bravebot":      {"brave.com"},
	"seranking":     {"seranking.com"},
}

// UnverifiableRecords persists when a claimed bot identity had no PTR. The
// verifier derives retry suppression and attempt history from that time and
// sweeps records older than the history. store.DB implements it.
type UnverifiableRecords interface {
	PutBotVerifyUnverifiable(ip net.IP, bot string, observedAt time.Time) error
	BotVerifyUnverifiable(ip net.IP, bot string) (observedAt time.Time, ok bool)
	SweepBotVerifyUnverifiable(cutoff time.Time) (int, error)
}

// NewAsyncBotVerifier constructs an async verifier backed by the
// system resolver. put is store.DB.PutBotVerify or a test seam; records is
// the store, or nil to keep no-PTR results in retry history only.
func NewAsyncBotVerifier(put func(net.IP, string, bool, time.Time) error, records UnverifiableRecords) *AsyncBotVerifier {
	res := net.DefaultResolver
	a := &AsyncBotVerifier{
		inflight:     make(map[string]time.Time),
		ch:           make(chan verifyJob, 256),
		v:            make(map[string]*verifier),
		res:          res,
		put:          put,
		unverifiable: records,
		stats:        queuehealth.New(256, time.Minute),
	}
	for bot, domains := range BotDomains {
		a.v[bot] = newVerifier(res, domains)
	}
	return a
}

// SetOperatorEntries rebuilds the per-bot verifier set from the built-in
// BotDomains plus operator-configured entries. An operator entry naming a
// built-in extends that bot's suffix list; a new name adds its own verifier.
// Safe to call after Run has started (SIGHUP reload): v is swapped under mu,
// which the worker also holds when reading it.
func (a *AsyncBotVerifier) SetOperatorEntries(entries []BotEntry) {
	entries = normalizeBotEntries(entries, false)
	m := make(map[string]*verifier, len(BotDomains)+len(entries))
	for bot, domains := range BotDomains {
		m[bot] = newVerifier(a.res, domains)
	}
	for _, e := range entries {
		if len(e.RDNSSuffixes) == 0 {
			continue
		}
		if existing, ok := m[e.Name]; ok {
			merged := append(append([]string(nil), existing.domains...), e.RDNSSuffixes...)
			m[e.Name] = newVerifier(a.res, merged)
		} else {
			m[e.Name] = newVerifier(a.res, e.RDNSSuffixes)
		}
	}
	a.mu.Lock()
	a.v = m
	a.mu.Unlock()
}

// Enqueue reports whether a job is queued or already in flight. Unsupported
// identities and unavailable capacity never receive pending treatment, and a
// source with a live no-PTR record is not queued again until it lapses.
func (a *AsyncBotVerifier) Enqueue(ip net.IP, bot string) bool {
	key := bot + "|" + ip.String()
	a.mu.Lock()
	defer a.mu.Unlock()
	// Serialize the record read with finish: a worker that writes after this
	// read must still be in flight when we decide whether to admit a retry.
	var recorded bool
	if a.unverifiable != nil {
		if observed, ok := a.unverifiable.BotVerifyUnverifiable(ip, bot); ok {
			now := time.Now()
			if !now.After(observed.Add(botVerifyUnverifiableTTL)) {
				return false
			}
			// A lapsed record still counts as an attempt for as long as
			// in-memory history would, so a restart or eviction cannot
			// grant fresh pending treatment.
			recorded = now.Before(observed.Add(botVerifyCacheTTL))
		}
	}
	if a.closed {
		a.stats.Lose(time.Now(), 1)
		return false
	}
	select {
	case <-a.stop:
		a.stats.Lose(time.Now(), 1)
		return false
	default:
	}
	if _, ok := a.inflight[key]; ok {
		return true
	}
	if ip == nil || a.v[bot] == nil {
		return false
	}
	now := time.Now()
	for attemptKey, previous := range a.attempts {
		_, live := a.inflight[attemptKey]
		if !live && !now.Before(previous.expiresAt) && !now.Before(previous.retryAfter) {
			delete(a.attempts, attemptKey)
		}
	}
	attempt, attempted := a.attempts[key]
	if attempted && now.Before(attempt.retryAfter) {
		return false
	}
	var replaceKey string
	if !attempted && len(a.attempts) >= cap(a.ch) {
		var oldest time.Time
		for attemptKey, previous := range a.attempts {
			if _, live := a.inflight[attemptKey]; live || now.Before(previous.retainUntil) {
				continue
			}
			if replaceKey == "" || previous.expiresAt.Before(oldest) {
				replaceKey = attemptKey
				oldest = previous.expiresAt
			}
		}
		if replaceKey == "" {
			a.stats.Lose(now, 1)
			return false
		}
	}
	var pendingUntil time.Time
	if !attempted && !recorded {
		pendingUntil = now.Add(botVerifyTimeout)
	}
	a.inflight[key] = pendingUntil
	// The caller may reuse its IP buffer as soon as admission returns. The
	// queued lookup and its dedup key must retain the same address.
	job := verifyJob{IP: slices.Clone(ip), Bot: bot, ticket: a.stats.Begin(time.Now())}
	select {
	case a.ch <- job:
		if !attempted {
			if a.attempts == nil {
				a.attempts = make(map[string]botVerifyAttempt)
			}
			delete(a.attempts, replaceKey)
			a.attempts[key] = botVerifyAttempt{
				retainUntil: now.Add(botVerifyRetryDelay),
				expiresAt:   now.Add(botVerifyCacheTTL),
			}
		}
		return true
	default:
		job.ticket.Reject(time.Now())
		delete(a.inflight, key)
		return false
	}
}

// Pending is true only while an admitted job is live and its initial grace
// has not expired. Queue wait counts against the same bound as a DNS lookup.
func (a *AsyncBotVerifier) Pending(ip net.IP, bot string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.v[bot] == nil {
		return false
	}
	select {
	case <-a.stop:
		return false
	default:
	}
	until, ok := a.inflight[bot+"|"+ip.String()]
	return ok && time.Now().Before(until)
}

const (
	botVerifyTimeout    = 5 * time.Second
	botVerifyRetryDelay = time.Minute
	botVerifyCacheTTL   = 24 * time.Hour
	// Shorter than a verdict: a crawler that gains a PTR is verified within
	// the hour, while a stable no-PTR source costs one lookup per hour.
	botVerifyUnverifiableTTL = time.Hour
)

func (a *AsyncBotVerifier) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return map[string]queuehealth.Status{"requests": a.stats.Snapshot(now)}
}

// Run processes the queue until stopCh closes. Runs as a single
// goroutine so DNS calls are serialised; volume is bounded by the
// inflight dedup map so bursts do not launch unbounded goroutines.
//
// Closing stopCh cancels the parent context, so any in-flight verify
// returns from its DNS lookup immediately rather than holding the Run
// goroutine for the per-job 5s timeout.
func (a *AsyncBotVerifier) Run(stopCh <-chan struct{}) {
	a.mu.Lock()
	a.stop = stopCh
	a.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())

	bridge := make(chan struct{})
	go func() {
		defer close(bridge)
		select {
		case <-stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	defer func() {
		cancel()
		<-bridge
		a.mu.Lock()
		a.closed = true
		close(a.ch)
		a.mu.Unlock()
		for job := range a.ch {
			a.finish(job, false, false)
		}
	}()

	for {
		select {
		case <-stopCh:
			return
		default:
		}
		select {
		case <-ctx.Done():
			return
		case job := <-a.ch:
			select {
			case <-stopCh:
				a.finish(job, false, false)
				return
			default:
			}
			a.processWithContext(ctx, job)
		}
	}
}

func (a *AsyncBotVerifier) process(job verifyJob) {
	a.processWithContext(context.Background(), job)
}

func (a *AsyncBotVerifier) processWithContext(parent context.Context, job verifyJob) {
	job.ticket.Start(time.Now())
	completed, cached := false, false
	defer func() { a.finish(job, completed, cached) }()

	a.mu.Lock()
	v, ok := a.v[job.Bot]
	a.mu.Unlock()
	if !ok {
		completed = true
		return
	}
	ctx, cancel := context.WithTimeout(parent, botVerifyTimeout)
	defer cancel()
	result, err := v.verify(ctx, job.IP, job.Bot)
	cancel()
	if err != nil {
		completed = errors.Is(err, ErrUnverifiable) && a.recordUnverifiable(job)
		return
	}
	if a.put == nil {
		completed = true
		return
	}
	cached = a.put(job.IP, job.Bot, result, time.Now().Add(botVerifyCacheTTL)) == nil
	completed = cached
}

// recordUnverifiable reports whether a no-PTR result is settled. It is not a
// verdict, so a lapsed record prevents fresh pending grace while within the
// history window. An unwritten record leaves the work unaccounted for.
func (a *AsyncBotVerifier) recordUnverifiable(job verifyJob) bool {
	if a.unverifiable == nil {
		return true
	}
	now := time.Now()
	if a.unverifiable.PutBotVerifyUnverifiable(job.IP, job.Bot, now) != nil {
		return false
	}
	// Records past the attempt history affect nothing. Sweeping after a write
	// bounds the bucket by recent no-PTR volume; once an hour keeps the scan
	// off the per-result path. Failures also wait an hour, so a failing large
	// transaction cannot hold up every subsequent result write.
	if now.Sub(a.unverifiableSwept) >= botVerifyUnverifiableTTL {
		a.unverifiableSwept = now
		_, _ = a.unverifiable.SweepBotVerifyUnverifiable(now.Add(-botVerifyCacheTTL))
	}
	return true
}

func (a *AsyncBotVerifier) finish(job verifyJob, completed, cached bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := job.Bot + "|" + job.IP.String()
	delete(a.inflight, key)
	if cached {
		delete(a.attempts, key)
	} else if attempt, tracked := a.attempts[key]; tracked {
		attempt.retryAfter = time.Now().Add(botVerifyRetryDelay)
		a.attempts[key] = attempt
	}
	if completed {
		job.ticket.Finish(time.Now())
	} else {
		job.ticket.Reject(time.Now())
	}
}
