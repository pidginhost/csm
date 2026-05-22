package threatintel

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type mockResolver struct {
	ptr map[string][]string
	a   map[string][]net.IP
	err error
}

func (m *mockResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
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

// IPs without a PTR record are unverifiable, not a confirmed spoof signal.
// Returning a negative here would mark every legitimate crawler IP without
// reverse DNS (Meta meta-externalagent, ClaudeBot on AWS) as a spoof.
func TestVerify_PTRNotFoundIsUnverifiable(t *testing.T) {
	res := &mockResolver{err: &net.DNSError{IsNotFound: true}}
	v := newVerifier(res, []string{"googlebot.com"})
	ok, err := v.verify(context.Background(), net.ParseIP("203.0.113.10"), "googlebot")
	if err == nil {
		t.Fatal("expected unverifiable error for missing PTR")
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
	if err == nil {
		t.Fatal("expected unverifiable error for empty PTR list")
	}
	if ok {
		t.Error("empty PTR must not verify true")
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
