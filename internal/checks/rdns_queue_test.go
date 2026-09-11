package checks

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

func rdnsQueueStatus(t *testing.T, c *RDNSCache, now time.Time) queuehealth.Status {
	t.Helper()
	source, ok := any(c).(interface {
		QueueStatuses(time.Time) map[string]queuehealth.Status
	})
	if !ok {
		t.Fatal("reverse DNS lookup slots have no queue health")
	}
	result := make(chan map[string]queuehealth.Status, 1)
	go func() { result <- source.QueueStatuses(now) }()
	select {
	case statuses := <-result:
		got, present := statuses["resolves"]
		if !present || len(statuses) != 1 {
			t.Fatalf("reverse DNS queue rows = %+v", statuses)
		}
		return got
	case <-time.After(time.Second):
		t.Fatal("reverse DNS health waited for cache or resolver")
		return queuehealth.Status{}
	}
}

func TestRDNSQueueHealthRetainsTimedOutResolver(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		releaseResolver := sync.OnceFunc(func() { close(release) })
		defer releaseResolver()
		var calls atomic.Int32
		c := NewRDNSCache(RDNSCacheConfig{
			TTL: time.Minute, ResolveDeadline: time.Second, MaxConcurrent: 1,
			Resolve: func(net.IP) (string, error) {
				if calls.Add(1) == 1 {
					<-release
				}
				return "host.example.com", nil
			},
		})
		result := make(chan string, 1)
		go func() { result <- c.Lookup(net.ParseIP("192.0.2.1")) }()
		synctest.Wait()
		status := rdnsQueueStatus(t, c, time.Now())
		if status.Depth != 0 || status.InFlight != 1 || status.Capacity != 1 || status.DroppedTotal != 0 || status.Status != "ok" {
			t.Fatalf("running lookup = %+v", status)
		}
		time.Sleep(2 * time.Second)
		if got := <-result; got != "" {
			t.Fatalf("deadline result = %q", got)
		}
		status = rdnsQueueStatus(t, c, time.Now())
		if status.Depth != 0 || status.InFlight != 1 || status.DroppedTotal != 1 || status.ProcessingSeconds != 2 || status.Reason != "processing_lag" {
			t.Fatalf("timeout hid unresolved work: %+v", status)
		}
		if got := c.Lookup(net.ParseIP("192.0.2.2")); got != "" {
			t.Fatalf("saturated lookup = %q", got)
		}
		status = rdnsQueueStatus(t, c, time.Now())
		if status.InFlight != 1 || status.DroppedTotal != 2 || calls.Load() != 1 {
			t.Fatalf("refusal accounting = %+v calls=%d", status, calls.Load())
		}
		releaseResolver()
		synctest.Wait()
		time.Sleep(time.Minute)
		if got := c.Lookup(net.ParseIP("192.0.2.3")); got != "host.example.com" {
			t.Fatalf("recovered lookup = %q", got)
		}
		synctest.Wait()
		status = rdnsQueueStatus(t, c, time.Now())
		if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 2 || status.Status != "ok" || calls.Load() != 2 {
			t.Fatalf("recovery accounting = %+v calls=%d", status, calls.Load())
		}
	})
}

func TestRDNSQueueHealthSeparatesNegativeResultsFromFailure(t *testing.T) {
	for _, negative := range []bool{false, true} {
		name := "failure"
		if negative {
			name = "nxdomain"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				c := NewRDNSCache(RDNSCacheConfig{
					TTL: time.Minute, ResolveDeadline: time.Second, MaxConcurrent: 2,
					Resolve: func(net.IP) (string, error) {
						calls.Add(1)
						if negative {
							return "", &net.DNSError{Err: "no such host", IsNotFound: true}
						}
						return "", errors.New("resolver unavailable")
					},
				})
				for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.1"} {
					if got := c.Lookup(net.ParseIP(ip)); got != "" {
						t.Fatalf("negative/error result = %q", got)
					}
				}
				if got := c.Lookup(nil); got != "" || calls.Load() != 3 {
					t.Fatalf("nil input or cache hit triggered lookup: result=%q calls=%d", got, calls.Load())
				}
				synctest.Wait()
				status := rdnsQueueStatus(t, c, time.Now())
				wantDrops, wantStatus := uint64(3), "degraded"
				if negative {
					wantDrops, wantStatus = 0, "ok"
				}
				if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != wantDrops || status.Status != wantStatus {
					t.Fatalf("negative/error accounting = %+v", status)
				}
			})
		})
	}
}

func TestRDNSQueueHealthConcurrentSaturation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		releaseResolver := sync.OnceFunc(func() { close(release) })
		defer releaseResolver()
		var calls atomic.Int32
		c := NewRDNSCache(RDNSCacheConfig{
			TTL: time.Minute, ResolveDeadline: time.Second, MaxConcurrent: 2,
			Resolve: func(net.IP) (string, error) {
				calls.Add(1)
				<-release
				return "host.example.com", nil
			},
		})
		var wg sync.WaitGroup
		for i := range 10 {
			wg.Go(func() {
				if got := c.Lookup(net.IPv4(192, 0, 2, byte(i+1))); got != "" {
					t.Errorf("saturated lookup returned %q", got)
				}
			})
		}
		synctest.Wait()
		status := rdnsQueueStatus(t, c, time.Now())
		if calls.Load() != 2 || len(c.sem) != 2 || status.Capacity != 2 || status.Depth != 0 || status.InFlight != 2 || status.DroppedTotal != 8 {
			t.Fatalf("saturation status = %+v calls=%d occupied=%d", status, calls.Load(), len(c.sem))
		}
		time.Sleep(2 * time.Second)
		wg.Wait()
		status = rdnsQueueStatus(t, c, time.Now())
		if calls.Load() != 2 || status.InFlight != 2 || status.DroppedTotal != 10 || status.ProcessingSeconds != 2 || status.Reason != "processing_lag" {
			t.Fatalf("abandoned callers hid resolver slots or lost counts: %+v", status)
		}
		releaseResolver()
		synctest.Wait()
		time.Sleep(time.Minute)
		status = rdnsQueueStatus(t, c, time.Now())
		if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 10 || status.Status != "ok" || len(c.sem) != 0 {
			t.Fatalf("released resolvers did not recover: %+v occupied=%d", status, len(c.sem))
		}
	})
}

func TestRDNSQueueHealthIgnoresCacheLock(t *testing.T) {
	c := NewRDNSCache(RDNSCacheConfig{ResolveDeadline: time.Second, MaxConcurrent: 2})
	c.mu.Lock()
	defer c.mu.Unlock()
	if status := rdnsQueueStatus(t, c, time.Now()); status.Status != "ok" || status.Capacity != 2 || status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 0 {
		t.Fatalf("idle slots with cache locked = %+v", status)
	}
}

func TestRDNSQueueHealthSynchronousModeHasNoSlots(t *testing.T) {
	c := NewRDNSCache(RDNSCacheConfig{MaxConcurrent: 2, Resolve: func(net.IP) (string, error) { return "host.example.com", nil }})
	c.sem <- struct{}{}
	if got := c.Lookup(net.ParseIP("192.0.2.1")); got != "host.example.com" {
		t.Fatalf("synchronous lookup = %q", got)
	}
	if rows := c.QueueStatuses(time.Now()); len(rows) != 0 || len(c.sem) != 1 {
		t.Fatalf("synchronous lookup published or used bounded slots: rows=%+v occupied=%d", rows, len(c.sem))
	}
}

func TestRDNSQueueHealthAbnormalResolverCountsOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := NewRDNSCache(RDNSCacheConfig{
			ResolveDeadline: time.Second, MaxConcurrent: 1,
			Resolve: func(net.IP) (string, error) { runtime.Goexit(); return "", nil },
		})
		if got := c.Lookup(net.ParseIP("192.0.2.1")); got != "" {
			t.Fatalf("abnormal resolver returned %q", got)
		}
		synctest.Wait()
		status := rdnsQueueStatus(t, c, time.Now())
		if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 1 || len(c.sem) != 0 {
			t.Fatalf("abnormal resolver and caller timeout accounting = %+v", status)
		}
	})
}
