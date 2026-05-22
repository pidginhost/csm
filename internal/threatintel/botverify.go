package threatintel

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
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
const LogicVersion = 2

// ErrUnverifiable signals that the resolver returned no usable PTR for
// the source IP, so the verifier cannot prove or disprove the claimed
// bot identity. Callers treat this as fail-open: do not cache, do not
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
// worker to skip the cache write so unverifiable IPs do not get pinned
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
	inflight map[string]struct{}
	ch       chan verifyJob
	v        map[string]*verifier // bot identity -> verifier
	put      func(net.IP, string, bool, time.Time) error
}

type verifyJob struct {
	IP  net.IP
	Bot string
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
}

// NewAsyncBotVerifier constructs an async verifier backed by the
// system resolver. put is store.DB.PutBotVerify or a test seam.
func NewAsyncBotVerifier(put func(net.IP, string, bool, time.Time) error) *AsyncBotVerifier {
	res := net.DefaultResolver
	a := &AsyncBotVerifier{
		inflight: make(map[string]struct{}),
		ch:       make(chan verifyJob, 256),
		v:        make(map[string]*verifier),
		put:      put,
	}
	for bot, domains := range BotDomains {
		a.v[bot] = newVerifier(res, domains)
	}
	return a
}

// Enqueue queues a verification job. Drops the request on a full queue
// (the scan path must never block on bot verification).
func (a *AsyncBotVerifier) Enqueue(ip net.IP, bot string) {
	key := bot + "|" + ip.String()
	a.mu.Lock()
	if _, ok := a.inflight[key]; ok {
		a.mu.Unlock()
		return
	}
	a.inflight[key] = struct{}{}
	a.mu.Unlock()

	select {
	case a.ch <- verifyJob{IP: ip, Bot: bot}:
	default:
		a.mu.Lock()
		delete(a.inflight, key)
		a.mu.Unlock()
	}
}

// Run processes the queue until stopCh closes. Runs as a single
// goroutine so DNS calls are serialised; volume is bounded by the
// inflight dedup map so bursts do not launch unbounded goroutines.
func (a *AsyncBotVerifier) Run(stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		case job := <-a.ch:
			a.process(job)
		}
	}
}

func (a *AsyncBotVerifier) process(job verifyJob) {
	defer a.finish(job)

	v, ok := a.v[job.Bot]
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	result, err := v.verify(ctx, job.IP, job.Bot)
	cancel()
	if err != nil || a.put == nil {
		return
	}
	_ = a.put(job.IP, job.Bot, result, time.Now().Add(24*time.Hour))
}

func (a *AsyncBotVerifier) finish(job verifyJob) {
	a.mu.Lock()
	delete(a.inflight, job.Bot+"|"+job.IP.String())
	a.mu.Unlock()
}
