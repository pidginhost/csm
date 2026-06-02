package challenge

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// fakeResolver is the test seam for DNS lookups. It also counts calls
// so cache-behaviour tests can assert that hits don't re-query.
type fakeResolver struct {
	addr      map[string][]string // ip -> PTR names
	host      map[string][]string // hostname -> A/AAAA addresses
	addrCalls atomic.Int64
	hostCalls atomic.Int64
	addrErr   error
	hostErr   error
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.addrCalls.Add(1)
	if f.addrErr != nil {
		return nil, f.addrErr
	}
	if names, ok := f.addr[addr]; ok {
		return names, nil
	}
	return nil, nil
}

func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	f.hostCalls.Add(1)
	if f.hostErr != nil {
		return nil, f.hostErr
	}
	if addrs, ok := f.host[host]; ok {
		return addrs, nil
	}
	return nil, nil
}

func TestCrawlerVerifierDisabledWhenNoProviders(t *testing.T) {
	v := NewCrawlerVerifier(nil, time.Minute, &fakeResolver{})
	if v.Enabled() {
		t.Error("Enabled = true with no providers")
	}
	if v.Verified(context.Background(), "1.2.3.4") {
		t.Error("Verified = true with no providers")
	}
}

func TestCrawlerVerifierUnknownProviderIgnored(t *testing.T) {
	v := NewCrawlerVerifier([]string{"yandexbot"}, time.Minute, &fakeResolver{})
	if v.Enabled() {
		t.Error("Enabled = true for unknown provider only")
	}
}

func TestCrawlerVerifierGooglebotMatchingPTRAndForward(t *testing.T) {
	r := &fakeResolver{
		addr: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
		},
		host: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
		},
	}
	v := NewCrawlerVerifier([]string{"googlebot"}, time.Minute, r)
	if !v.Verified(context.Background(), "66.249.66.1") {
		t.Error("Verified = false for matching PTR + forward")
	}
}

func TestCrawlerVerifierSpoofedUARejectedOnForwardMismatch(t *testing.T) {
	// PTR matches googlebot suffix but the forward resolves to a
	// different IP -- the spoof case.
	r := &fakeResolver{
		addr: map[string][]string{
			"6.6.6.6": {"fake.googlebot.com."},
		},
		host: map[string][]string{
			"fake.googlebot.com": {"66.249.66.1"}, // not 6.6.6.6
		},
	}
	v := NewCrawlerVerifier([]string{"googlebot"}, time.Minute, r)
	if v.Verified(context.Background(), "6.6.6.6") {
		t.Error("Verified = true on spoofed UA / mismatched forward")
	}
}

func TestCrawlerVerifierWrongSuffixRejected(t *testing.T) {
	r := &fakeResolver{
		addr: map[string][]string{
			"5.5.5.5": {"random-host.example.com."},
		},
		host: map[string][]string{
			"random-host.example.com": {"5.5.5.5"},
		},
	}
	v := NewCrawlerVerifier([]string{"googlebot", "bingbot"}, time.Minute, r)
	if v.Verified(context.Background(), "5.5.5.5") {
		t.Error("Verified = true for non-crawler PTR")
	}
}

func TestCrawlerVerifierBingbotMatch(t *testing.T) {
	r := &fakeResolver{
		addr: map[string][]string{
			"40.77.167.1": {"msnbot-40-77-167-1.search.msn.com."},
		},
		host: map[string][]string{
			"msnbot-40-77-167-1.search.msn.com": {"40.77.167.1"},
		},
	}
	v := NewCrawlerVerifier([]string{"bingbot"}, time.Minute, r)
	if !v.Verified(context.Background(), "40.77.167.1") {
		t.Error("Verified = false for matching bingbot PTR + forward")
	}
}

func TestCrawlerVerifierPositiveCacheSkipsDNS(t *testing.T) {
	r := &fakeResolver{
		addr: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
		},
		host: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
		},
	}
	v := NewCrawlerVerifier([]string{"googlebot"}, time.Minute, r)
	if !v.Verified(context.Background(), "66.249.66.1") {
		t.Fatal("first Verified = false")
	}
	addrCalls := r.addrCalls.Load()
	hostCalls := r.hostCalls.Load()

	// Second call should hit the cache, no new DNS.
	if !v.Verified(context.Background(), "66.249.66.1") {
		t.Fatal("cached Verified = false")
	}
	if r.addrCalls.Load() != addrCalls {
		t.Errorf("LookupAddr called on cached hit (was %d, now %d)", addrCalls, r.addrCalls.Load())
	}
	if r.hostCalls.Load() != hostCalls {
		t.Errorf("LookupHost called on cached hit (was %d, now %d)", hostCalls, r.hostCalls.Load())
	}
}

func TestCrawlerVerifierNegativeCacheSkipsDNS(t *testing.T) {
	r := &fakeResolver{
		addr: map[string][]string{
			"5.5.5.5": {"random.example.com."},
		},
	}
	v := NewCrawlerVerifier([]string{"googlebot"}, time.Minute, r)
	if v.Verified(context.Background(), "5.5.5.5") {
		t.Fatal("first Verified = true (expected false for non-crawler)")
	}
	addrCalls := r.addrCalls.Load()
	if v.Verified(context.Background(), "5.5.5.5") {
		t.Fatal("cached negative -> true")
	}
	if r.addrCalls.Load() != addrCalls {
		t.Errorf("LookupAddr called on cached negative")
	}
}

func TestCrawlerVerifierResolverErrorTreatedAsNotVerified(t *testing.T) {
	r := &fakeResolver{addrErr: errors.New("dns down")}
	v := NewCrawlerVerifier([]string{"googlebot"}, time.Minute, r)
	if v.Verified(context.Background(), "1.2.3.4") {
		t.Error("Verified = true on resolver error")
	}
}

func TestCrawlerVerifierCacheExpiry(t *testing.T) {
	r := &fakeResolver{
		addr: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
		},
		host: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
		},
	}
	// 50ms positive TTL (10ms negative). Sleep past it and the cache
	// entry should be re-fetched.
	v := NewCrawlerVerifier([]string{"googlebot"}, 50*time.Millisecond, r)
	if !v.Verified(context.Background(), "66.249.66.1") {
		t.Fatal("first Verified = false")
	}
	addrCalls := r.addrCalls.Load()
	time.Sleep(80 * time.Millisecond)
	if !v.Verified(context.Background(), "66.249.66.1") {
		t.Fatal("post-expiry Verified = false")
	}
	if r.addrCalls.Load() == addrCalls {
		t.Error("LookupAddr not re-called after TTL expiry")
	}
}

// cachePut must not let the verifier cache grow without bound between the
// daemon's periodic prunes. A flood of unique source IPs (each a negative
// cache miss) must stay capped, evicting older entries to make room.
func TestCrawlerVerifierCacheIsBounded(t *testing.T) {
	v := NewCrawlerVerifier([]string{"googlebot"}, time.Minute, &fakeResolver{})
	v.maxSize = 100

	for i := 0; i < 10000; i++ {
		v.cachePut(fmtIP(i), false)
	}

	v.mu.Lock()
	size := len(v.cache)
	v.mu.Unlock()
	if size > v.maxSize {
		t.Fatalf("cache size %d exceeded cap %d", size, v.maxSize)
	}
}

func fmtIP(i int) string {
	return "203.0.113." + itoa(i%256) + ":" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
