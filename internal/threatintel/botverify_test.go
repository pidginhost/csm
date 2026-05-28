package threatintel

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type mockResolver struct {
	ptr     map[string][]string
	a       map[string][]net.IP
	err     error
	addrErr error
	ipErr   error
}

func (m *mockResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.addrErr != nil {
		return nil, m.addrErr
	}
	if m.err != nil {
		return nil, m.err
	}
	return m.ptr[ip], nil
}

func (m *mockResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.ipErr != nil {
		return nil, m.ipErr
	}
	if m.err != nil {
		return nil, m.err
	}
	return m.a[host], nil
}

func TestVerify_PositiveGooglebot(t *testing.T) {
	ip := "66.249.66.99"
	// PTR returns FQDN with trailing dot; forward-A lookup uses the
	// TrimSuffix'd name (no trailing dot).
	res := &mockResolver{
		ptr: map[string][]string{ip: {"crawl-66-249-66-99.googlebot.com."}},
		a:   map[string][]net.IP{"crawl-66-249-66-99.googlebot.com": {net.ParseIP(ip)}},
	}
	v := newVerifier(res, []string{"googlebot.com", "google.com"})
	ok, err := v.verify(context.Background(), net.ParseIP(ip), "googlebot")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected positive verify")
	}
}

func TestVerify_PTRMismatch(t *testing.T) {
	ip := "66.249.66.99"
	res := &mockResolver{
		ptr: map[string][]string{ip: {"some-evil-host.example.com."}},
	}
	v := newVerifier(res, []string{"googlebot.com"})
	ok, err := v.verify(context.Background(), net.ParseIP(ip), "googlebot")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("PTR domain mismatch must verify-fail")
	}
}

func TestVerify_PTRTransientErrorFailsOpen(t *testing.T) {
	res := &mockResolver{err: errors.New("temporary resolver failure")}
	v := newVerifier(res, []string{"googlebot.com"})
	ok, err := v.verify(context.Background(), net.ParseIP("203.0.113.10"), "googlebot")
	if err == nil {
		t.Fatal("expected resolver error")
	}
	if ok {
		t.Error("resolver error must not verify true")
	}
}

func TestVerify_ForwardNotFoundIsDefinitiveNegative(t *testing.T) {
	ip := "66.249.66.99"
	res := &mockResolver{
		ptr:   map[string][]string{ip: {"crawl-66-249-66-99.googlebot.com."}},
		ipErr: &net.DNSError{IsNotFound: true},
	}
	v := newVerifier(res, []string{"googlebot.com"})
	ok, err := v.verify(context.Background(), net.ParseIP(ip), "googlebot")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("forward not-found must verify-fail")
	}
}

func TestVerify_ForwardTransientErrorFailsOpen(t *testing.T) {
	ip := "66.249.66.99"
	res := &mockResolver{
		ptr:   map[string][]string{ip: {"crawl-66-249-66-99.googlebot.com."}},
		ipErr: errors.New("temporary resolver failure"),
	}
	v := newVerifier(res, []string{"googlebot.com"})
	ok, err := v.verify(context.Background(), net.ParseIP(ip), "googlebot")
	if err == nil {
		t.Fatal("expected resolver error")
	}
	if ok {
		t.Error("resolver error must not verify true")
	}
}

// IPs without a PTR record are unverifiable, not a confirmed spoof signal.
// Returning a negative here would mark every legitimate crawler IP without
// reverse DNS (Meta meta-externalagent, ClaudeBot on AWS) as a spoof.
func TestVerify_PTRNotFoundIsUnverifiable(t *testing.T) {
	res := &mockResolver{err: &net.DNSError{IsNotFound: true}}
	v := newVerifier(res, []string{"googlebot.com"})
	ok, err := v.verify(context.Background(), net.ParseIP("203.0.113.10"), "googlebot")
	if !errors.Is(err, ErrUnverifiable) {
		t.Fatalf("error = %v, want ErrUnverifiable", err)
	}
	if ok {
		t.Error("no-PTR must not verify true")
	}
}

func TestVerify_EmptyPTRListIsUnverifiable(t *testing.T) {
	ip := "203.0.113.10"
	res := &mockResolver{ptr: map[string][]string{ip: nil}}
	v := newVerifier(res, []string{"googlebot.com"})
	ok, err := v.verify(context.Background(), net.ParseIP(ip), "googlebot")
	if !errors.Is(err, ErrUnverifiable) {
		t.Fatalf("error = %v, want ErrUnverifiable", err)
	}
	if ok {
		t.Error("empty PTR must not verify true")
	}
}

// Real Meta crawler IPs use fbsv.net for reverse DNS (e.g.,
// fwdproxy-ncg-116.fbsv.net.), not facebook.com.
func TestVerify_FacebookbotFbsvNetSuffix(t *testing.T) {
	ip := "69.63.184.116"
	res := &mockResolver{
		ptr: map[string][]string{ip: {"fwdproxy-ncg-116.fbsv.net."}},
		a:   map[string][]net.IP{"fwdproxy-ncg-116.fbsv.net": {net.ParseIP(ip)}},
	}
	v := newVerifier(res, BotDomains["facebookbot"])
	ok, err := v.verify(context.Background(), net.ParseIP(ip), "facebookbot")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("Meta fwdproxy.fbsv.net FCrDNS must verify positive")
	}
}

// Real Amazonbot rDNS uses Amazon's .amazon gTLD (e.g.,
// 35-172-125-172.crawl.amazonbot.amazon.), not amazon.com.
func TestVerify_AmazonbotDotAmazonSuffix(t *testing.T) {
	ip := "35.172.125.172"
	res := &mockResolver{
		ptr: map[string][]string{ip: {"35-172-125-172.crawl.amazonbot.amazon."}},
		a:   map[string][]net.IP{"35-172-125-172.crawl.amazonbot.amazon": {net.ParseIP(ip)}},
	}
	v := newVerifier(res, BotDomains["amazonbot"])
	ok, err := v.verify(context.Background(), net.ParseIP(ip), "amazonbot")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("Amazonbot crawl.amazonbot.amazon FCrDNS must verify positive")
	}
}

func TestAsyncBotVerifier_DoesNotCacheNoPTR(t *testing.T) {
	var puts int
	a := NewAsyncBotVerifier(func(net.IP, string, bool, time.Time) error {
		puts++
		return nil
	})
	a.v["googlebot"] = newVerifier(&mockResolver{err: &net.DNSError{IsNotFound: true}}, []string{"googlebot.com"})

	a.process(verifyJob{IP: net.ParseIP("203.0.113.10"), Bot: "googlebot"})

	if puts != 0 {
		t.Fatalf("no-PTR wrote %d cache entries, want 0", puts)
	}
}

func TestVerify_DeadlineHonored(t *testing.T) {
	res := &mockResolver{}
	v := newVerifier(res, []string{"googlebot.com"})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	_, err := v.verify(ctx, net.ParseIP("66.249.66.99"), "googlebot")
	if err == nil {
		t.Error("expected context deadline error")
	}
}

// blockingResolver stalls until ctx.Done() fires. Lets the test pin a
// LookupAddr in flight inside process() and verify that closing stopCh
// cancels the per-job context before the 5s hard timeout.
type blockingResolver struct {
	started chan struct{}
}

func (b *blockingResolver) LookupAddr(ctx context.Context, _ string) ([]string, error) {
	select {
	case <-b.started:
	default:
		close(b.started)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (b *blockingResolver) LookupIP(ctx context.Context, _, _ string) ([]net.IP, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type forwardBlockingResolver struct {
	started chan struct{}
	ptr     string
}

func (f *forwardBlockingResolver) LookupAddr(context.Context, string) ([]string, error) {
	return []string{f.ptr}, nil
}

func (f *forwardBlockingResolver) LookupIP(ctx context.Context, _, _ string) ([]net.IP, error) {
	select {
	case <-f.started:
	default:
		close(f.started)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// A daemon shutdown that closes stopCh must cancel the per-job context
// of any verify currently mid-LookupAddr, instead of leaving Run blocked
// for 5 seconds while the worker waits on its own timeout.
func TestAsyncBotVerifier_CancelsInflightOnShutdown(t *testing.T) {
	started := make(chan struct{})
	res := &blockingResolver{started: started}
	a := &AsyncBotVerifier{
		inflight: make(map[string]struct{}),
		ch:       make(chan verifyJob, 4),
		v:        map[string]*verifier{"googlebot": newVerifier(res, []string{"googlebot.com"})},
		put:      func(net.IP, string, bool, time.Time) error { return nil },
	}

	stopCh := make(chan struct{})
	runDone := make(chan struct{})
	go func() {
		a.Run(stopCh)
		close(runDone)
	}()

	a.Enqueue(net.ParseIP("66.249.66.99"), "googlebot")
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("LookupAddr was not called within 1s")
	}

	close(stopCh)
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after stopCh; in-flight verify is not honoring daemon shutdown")
	}
}

func TestAsyncBotVerifier_CancelsForwardLookupOnShutdown(t *testing.T) {
	started := make(chan struct{})
	res := &forwardBlockingResolver{
		started: started,
		ptr:     "crawl-66-249-66-99.googlebot.com.",
	}
	a := &AsyncBotVerifier{
		inflight: make(map[string]struct{}),
		ch:       make(chan verifyJob, 4),
		v:        map[string]*verifier{"googlebot": newVerifier(res, []string{"googlebot.com"})},
		put:      func(net.IP, string, bool, time.Time) error { return nil },
	}

	stopCh := make(chan struct{})
	runDone := make(chan struct{})
	go func() {
		a.Run(stopCh)
		close(runDone)
	}()

	a.Enqueue(net.ParseIP("66.249.66.99"), "googlebot")
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("LookupIP was not called within 1s")
	}

	close(stopCh)
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after stopCh; forward lookup is not honoring daemon shutdown")
	}
}

func TestAsyncBotVerifier_DoesNotCacheTransientErrors(t *testing.T) {
	var puts int
	a := NewAsyncBotVerifier(func(net.IP, string, bool, time.Time) error {
		puts++
		return nil
	})
	a.v["googlebot"] = newVerifier(&mockResolver{err: errors.New("temporary resolver failure")}, []string{"googlebot.com"})

	a.process(verifyJob{IP: net.ParseIP("203.0.113.10"), Bot: "googlebot"})

	if puts != 0 {
		t.Fatalf("transient resolver error wrote %d cache entries, want 0", puts)
	}
}
