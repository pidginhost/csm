package checks

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type rdnsWork struct {
	cache     *RDNSCache
	ticket    queuehealth.Ticket
	remaining atomic.Int32
	failOnce  sync.Once
}

type rdnsResult struct {
	host string
	err  error
}

func (c *RDNSCache) acquireResolve() *rdnsWork {
	ticket := c.stats.Begin(time.Now())
	select {
	case c.sem <- struct{}{}:
		work := &rdnsWork{cache: c, ticket: ticket}
		work.remaining.Store(2)
		return work
	default:
		ticket.Reject(time.Now())
		return nil
	}
}

func (w *rdnsWork) fail() {
	w.failOnce.Do(func() { w.cache.stats.Lose(time.Now(), 1) })
}

func (w *rdnsWork) release() {
	// The caller can leave while DNS still runs, or DNS can return before
	// its caller receives the buffered result. Both own the admitted slot.
	if w.remaining.Add(-1) == 0 {
		w.ticket.Finish(time.Now())
		<-w.cache.sem
	}
}

func (c *RDNSCache) resolveTracked(work *rdnsWork, ip net.IP, done chan<- rdnsResult) {
	work.ticket.Start(time.Now())
	completed := false
	defer func() {
		if !completed {
			work.fail()
		}
		work.release()
	}()
	host, err := c.resolve(ip)
	var dnsErr *net.DNSError
	if err != nil && (!errors.As(err, &dnsErr) || !dnsErr.IsNotFound) {
		work.fail()
	}
	done <- rdnsResult{host: host, err: err}
	completed = true
}

// QueueStatuses reads memory only. Without a deadline, Lookup is synchronous
// and does not use this bounded resolver pool.
func (c *RDNSCache) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	if c.stats == nil {
		return nil
	}
	return map[string]queuehealth.Status{"resolves": c.stats.Snapshot(now)}
}
