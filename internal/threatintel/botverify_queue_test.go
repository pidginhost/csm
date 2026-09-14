package threatintel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

func botQueueStatus(t *testing.T, a *AsyncBotVerifier) queuehealth.Status {
	t.Helper()
	source, ok := any(a).(interface {
		QueueStatuses(time.Time) map[string]queuehealth.Status
	})
	if !ok {
		t.Fatal("bot verification has no queue health")
	}
	status, ok := source.QueueStatuses(time.Now())["requests"]
	if !ok {
		t.Fatal("bot verification request queue is missing")
	}
	return status
}

func TestBotQueueMeasuresOverflowAndCoalescedAge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := NewAsyncBotVerifier(nil, nil)
		for i := range 256 {
			a.Enqueue(net.ParseIP(fmt.Sprintf("192.0.2.%d", i)), "googlebot")
		}
		a.Enqueue(net.ParseIP("198.51.100.1"), "googlebot")
		a.Enqueue(net.ParseIP("198.51.100.2"), "googlebot")
		time.Sleep(61 * time.Second)
		for range 5 {
			a.Enqueue(net.ParseIP("192.0.2.1"), "googlebot")
		}
		got := botQueueStatus(t, a)
		if got.Depth != 256 || got.Capacity != 256 || got.InFlight != 0 || got.DroppedTotal != 2 || got.LagSeconds != 61 || got.Status != "degraded" {
			t.Fatalf("overflow or coalescing concealed retained requests: %+v", got)
		}
		if len(a.inflight) != 256 {
			t.Fatalf("pending keys escaped capacity: %d", len(a.inflight))
		}
		stop := make(chan struct{})
		close(stop)
		a.Run(stop)
		got = botQueueStatus(t, a)
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 258 || len(a.inflight) != 0 {
			t.Fatalf("shutdown lost refused or abandoned requests: %+v keys=%d", got, len(a.inflight))
		}
	})
}

type botQueueResolver struct {
	lookup func(context.Context, string) ([]string, error)
}

func (r botQueueResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	return r.lookup(ctx, ip)
}

func (botQueueResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return nil, errors.New("unexpected forward lookup")
}

func TestBotQueueShutdownRetainsRunningCacheWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stop, release := make(chan struct{}), make(chan struct{})
		stopLoop := sync.OnceFunc(func() { close(stop) })
		releasePut := sync.OnceFunc(func() { close(release) })
		var lookups, writes atomic.Int32
		a := NewAsyncBotVerifier(func(net.IP, string, bool, time.Time) error {
			writes.Add(1)
			<-release
			return errors.New("cache unavailable")
		}, nil)
		a.v["googlebot"] = newVerifier(botQueueResolver{lookup: func(context.Context, string) ([]string, error) {
			lookups.Add(1)
			return []string{"crawler.example"}, nil
		}}, []string{"googlebot.com"})
		done := make(chan struct{})
		go func() { defer close(done); a.Run(stop) }()
		defer func() { stopLoop(); releasePut(); <-done }()
		a.Enqueue(net.ParseIP("192.0.2.1"), "googlebot")
		synctest.Wait()
		for i := 2; i <= 4; i++ {
			a.Enqueue(net.ParseIP(fmt.Sprintf("192.0.2.%d", i)), "googlebot")
		}
		time.Sleep(61 * time.Second)
		got := botQueueStatus(t, a)
		if got.Depth != 3 || got.InFlight != 1 || got.LagSeconds != 61 || got.ProcessingSeconds != 61 || got.Status != "degraded" {
			t.Fatalf("blocked cache write hid queued or running work: %+v", got)
		}
		captured := a.Enqueue
		stopLoop()
		captured(net.ParseIP("192.0.2.5"), "googlebot")
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("shutdown returned while cache write remained active")
		default:
		}
		releasePut()
		<-done
		got = botQueueStatus(t, a)
		if lookups.Load() != 1 || writes.Load() != 1 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 5 || len(a.inflight) != 0 {
			t.Fatalf("shutdown started or lost abandoned work: lookups=%d writes=%d status=%+v keys=%d", lookups.Load(), writes.Load(), got, len(a.inflight))
		}
		captured(net.ParseIP("192.0.2.6"), "googlebot")
		got = botQueueStatus(t, a)
		if got.Depth != 0 || got.DroppedTotal != 6 || len(a.inflight) != 0 {
			t.Fatalf("captured producer accepted work after shutdown: %+v keys=%d", got, len(a.inflight))
		}
	})
}

func TestBotQueueDistinguishesFailuresFromVerificationResults(t *testing.T) {
	ip := net.ParseIP("192.0.2.1")
	for _, tc := range []struct {
		name      string
		res       resolver
		bot       string
		putErr    error
		wantPuts  int
		wantValue bool
		wantLost  uint64
	}{
		{name: "missing PTR", res: &mockResolver{err: &net.DNSError{IsNotFound: true}}, bot: "googlebot"},
		{name: "unknown identity", res: &mockResolver{}, bot: "unknown"},
		{name: "negative", res: &mockResolver{ptr: map[string][]string{ip.String(): {"crawler.example"}}}, bot: "googlebot", wantPuts: 2},
		{name: "positive", res: &mockResolver{ptr: map[string][]string{ip.String(): {"crawler.googlebot.com"}}, a: map[string][]net.IP{"crawler.googlebot.com": {ip}}}, bot: "googlebot", wantPuts: 2, wantValue: true},
		{name: "DNS failure", res: &mockResolver{err: errors.New("DNS unavailable")}, bot: "googlebot", wantLost: 2},
		{name: "DNS deadline", res: botQueueResolver{lookup: func(ctx context.Context, _ string) ([]string, error) { <-ctx.Done(); return nil, ctx.Err() }}, bot: "googlebot", wantLost: 2},
		{name: "cache failure", res: &mockResolver{ptr: map[string][]string{ip.String(): {"crawler.example"}}}, bot: "googlebot", putErr: errors.New("cache unavailable"), wantPuts: 2, wantLost: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				stop := make(chan struct{})
				var values []bool
				a := NewAsyncBotVerifier(func(_ net.IP, _ string, value bool, _ time.Time) error {
					values = append(values, value)
					return tc.putErr
				}, nil)
				a.v["googlebot"] = newVerifier(tc.res, []string{"googlebot.com"})
				done := make(chan struct{})
				go func() { defer close(done); a.Run(stop) }()
				for range 2 {
					a.Enqueue(ip, tc.bot)
					synctest.Wait()
					// Exercise a real retry after both the DNS deadline and the
					// unresolved-attempt cooldown, preserving the two-attempt counts.
					time.Sleep(botVerifyTimeout + botVerifyRetryDelay + time.Second)
					synctest.Wait()
				}
				close(stop)
				<-done
				got := botQueueStatus(t, a)
				if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != tc.wantLost || len(values) != tc.wantPuts || len(a.inflight) != 0 {
					t.Fatalf("completion/retry changed verification policy: status=%+v puts=%v keys=%d", got, values, len(a.inflight))
				}
				for _, value := range values {
					if value != tc.wantValue {
						t.Fatalf("cached result=%v, want %v", value, tc.wantValue)
					}
				}
			})
		})
	}
}

func TestBotQueuePanicSettlesOwnedAndAbandonedRequests(t *testing.T) {
	a := NewAsyncBotVerifier(func(net.IP, string, bool, time.Time) error { panic("cache failed") }, nil)
	a.v["googlebot"] = newVerifier(botQueueResolver{lookup: func(context.Context, string) ([]string, error) {
		return []string{"crawler.example"}, nil
	}}, []string{"googlebot.com"})
	for i := 1; i <= 3; i++ {
		a.Enqueue(net.ParseIP(fmt.Sprintf("192.0.2.%d", i)), "googlebot")
	}
	var caught any
	func() { defer func() { caught = recover() }(); a.Run(make(chan struct{})) }()
	if caught != "cache failed" {
		t.Fatalf("cache panic was concealed: %v", caught)
	}
	if len(a.inflight) != 0 {
		t.Fatalf("panic abandoned %d pending verification keys", len(a.inflight))
	}
	got := botQueueStatus(t, a)
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || len(a.inflight) != 0 {
		t.Fatalf("panic lost queue or dedup state: %+v keys=%d", got, len(a.inflight))
	}
}

func TestBotQueueRejectsAfterWorkerReturns(t *testing.T) {
	a := NewAsyncBotVerifier(nil, nil)
	stop := make(chan struct{})
	close(stop)
	a.Run(stop)
	a.Enqueue(net.ParseIP("192.0.2.1"), "googlebot")
	if len(a.inflight) != 0 {
		t.Fatalf("stopped worker accepted %d requests without a consumer", len(a.inflight))
	}
	got := botQueueStatus(t, a)
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 {
		t.Fatalf("late request was not recorded as lost: %+v", got)
	}
}

func TestBotQueueOwnsAdmittedIP(t *testing.T) {
	stop := make(chan struct{})
	var lookedUp, cached string
	a := NewAsyncBotVerifier(func(ip net.IP, _ string, _ bool, _ time.Time) error {
		cached = ip.String()
		close(stop)
		return nil
	}, nil)
	a.v["googlebot"] = newVerifier(botQueueResolver{lookup: func(_ context.Context, ip string) ([]string, error) {
		lookedUp = ip
		return []string{"crawler.example"}, nil
	}}, []string{"googlebot.com"})
	ip := net.ParseIP("192.0.2.1")
	a.Enqueue(ip, "googlebot")
	ip[len(ip)-1] = 99
	a.Run(stop)
	if lookedUp != "192.0.2.1" || cached != "192.0.2.1" || len(a.inflight) != 0 {
		t.Fatalf("caller mutation changed the request identity: lookup=%s cached=%s keys=%d", lookedUp, cached, len(a.inflight))
	}
	got := botQueueStatus(t, a)
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
		t.Fatalf("completed request ownership was lost: %+v", got)
	}
}

func TestBotQueueConcurrentShutdownConservesRequests(t *testing.T) {
	a := NewAsyncBotVerifier(nil, nil)
	a.v["googlebot"] = newVerifier(&mockResolver{err: errors.New("resolver unavailable")}, []string{"googlebot.com"})
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { defer close(done); a.Run(stop) }()
	start := make(chan struct{})
	var producers sync.WaitGroup
	for p := range 4 {
		producers.Go(func() {
			<-start
			for n := range 64 {
				a.Enqueue(net.ParseIP(fmt.Sprintf("192.0.2.%d", p*64+n)), "googlebot")
			}
		})
	}
	producers.Go(func() { <-start; close(stop) })
	close(start)
	producers.Wait()
	<-done
	got := botQueueStatus(t, a)
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 256 || len(a.inflight) != 0 {
		t.Fatalf("concurrent shutdown lost requests: %+v keys=%d", got, len(a.inflight))
	}
}
