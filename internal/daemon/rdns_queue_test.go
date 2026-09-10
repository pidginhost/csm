package daemon

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

func TestDaemonReportsRDNSLookupSlotsWithoutResolving(t *testing.T) {
	var calls atomic.Int32
	c := checks.NewRDNSCache(checks.RDNSCacheConfig{
		TTL: time.Minute, ResolveDeadline: time.Second, MaxConcurrent: 2,
		Resolve: func(net.IP) (string, error) { calls.Add(1); return "host.example.com", nil },
	})
	installDirectSMTPRDNSCacheForTest(t, c)
	d := &Daemon{}
	status, ok := d.QueueStatuses()["smtp_rdns.resolves"]
	if !ok || status.Capacity != 2 || status.Depth != 0 || status.InFlight != 0 || status.Status != "ok" || calls.Load() != 0 {
		t.Fatalf("idle lookup health = %+v present=%v resolver calls=%d", status, ok, calls.Load())
	}
}

func TestDaemonReportsRDNSAfterCallerTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		releaseResolver := sync.OnceFunc(func() { close(release) })
		defer releaseResolver()
		var calls atomic.Int32
		c := checks.NewRDNSCache(checks.RDNSCacheConfig{
			TTL: time.Minute, ResolveDeadline: time.Second, MaxConcurrent: 2,
			Resolve: func(net.IP) (string, error) { calls.Add(1); <-release; return "host.example.com", nil },
		})
		installDirectSMTPRDNSCacheForTest(t, c)
		result := make(chan string, 1)
		go func() { result <- c.Lookup(net.ParseIP("192.0.2.1")) }()
		synctest.Wait()
		time.Sleep(2 * time.Second)
		if got := <-result; got != "" {
			t.Fatalf("deadline result = %q", got)
		}
		d := &Daemon{}
		status, ok := d.QueueStatuses()["smtp_rdns.resolves"]
		if !ok || status.Capacity != 2 || status.Depth != 0 || status.InFlight != 1 || status.DroppedTotal != 1 || status.ProcessingSeconds != 2 || status.Reason != "processing_lag" || calls.Load() != 1 {
			t.Fatalf("stalled lookup health = %+v present=%v calls=%d", status, ok, calls.Load())
		}
		releaseResolver()
		synctest.Wait()
		time.Sleep(time.Minute)
		status = d.QueueStatuses()["smtp_rdns.resolves"]
		if status.Status != "ok" || status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 1 || calls.Load() != 1 {
			t.Fatalf("recovered lookup health = %+v calls=%d", status, calls.Load())
		}
	})
}
