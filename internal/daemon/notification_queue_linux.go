//go:build linux

package daemon

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type notificationSource interface {
	Pending() (int, error)
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

type fanotifyDescriptor int

func (fd fanotifyDescriptor) Pending() (int, error) {
	bytes, err := unix.IoctlGetInt(int(fd), unix.TIOCINQ)
	if err != nil {
		return 0, err
	}
	// Fanotify's FIONREAD counts metadata headers, including overflow records.
	if bytes < 0 || bytes%metadataSize != 0 {
		return 0, fmt.Errorf("invalid fanotify pending byte count: %d", bytes)
	}
	return bytes / metadataSize, nil
}

func (fd fanotifyDescriptor) Read(buf []byte) (int, error)  { return unix.Read(int(fd), buf) }
func (fd fanotifyDescriptor) Write(buf []byte) (int, error) { return unix.Write(int(fd), buf) }
func (fd fanotifyDescriptor) Close() error                  { return unix.Close(int(fd)) }

// Notification descriptors are nonblocking. Serialize their syscalls with
// close so health reads and permission responses cannot use a recycled fd.
// Parsing runs outside that lock and keeps its own tracked batch.
type notificationQueue struct {
	mu              sync.Mutex
	source          notificationSource
	sampled         *queuehealth.Sampled
	losses          *queuehealth.Tracker
	batches         *queuehealth.Tracker
	consumed        uint64
	closed          bool
	closeErr        error
	unavailable     bool
	variableRecords bool
}

func newNotificationQueue(source notificationSource, losses, batches *queuehealth.Tracker) *notificationQueue {
	return &notificationQueue{
		source: source, losses: losses, batches: batches,
		sampled: queuehealth.NewSampled(0, "records", time.Minute),
	}
}

func (q *notificationQueue) snapshot(now func() time.Time) (kernel, reader queuehealth.Status) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		pending, err := q.source.Pending()
		q.unavailable = err != nil || pending < 0
		if !q.unavailable {
			q.sampled.Observe(now(), pending, q.consumed)
		}
	}
	kernel = q.sampled.Snapshot(now())
	losses := q.losses.Snapshot(now())
	kernel.DroppedTotal, kernel.RecentDrops = losses.DroppedTotal, losses.RecentDrops
	if kernel.Reason == "" && losses.Status == "degraded" {
		kernel.Status, kernel.Reason = losses.Status, losses.Reason
	}
	// The group limit is not exposed. The current sysctl can differ from the
	// value copied at creation. An overflow marker also omits its loss count.
	kernel.CapacityUnavailable, kernel.DroppedLowerBound = true, true
	if q.unavailable {
		kernel.Status, kernel.Reason = "degraded", "measurement_unavailable"
		if !q.closed {
			kernel.Depth, kernel.LagSeconds = 0, 0
			kernel.DepthUnavailable, kernel.LagBasis = true, "unavailable"
		}
	}
	reader = q.batches.Snapshot(now())
	reader.DepthUnit = "batches"
	return kernel, reader
}

func (q *notificationQueue) read(buf []byte, process func([]byte)) (int, error) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return 0, unix.EBADF
	}
	n, err := q.source.Read(buf)
	if err != nil || n <= 0 {
		q.mu.Unlock()
		return n, err
	}
	q.consumed++
	work := queuehealth.Work[[]byte]{Value: buf[:n], Ticket: q.batches.Begin(time.Now())}
	q.mu.Unlock()
	work.Process(process)
	return n, err
}

func (q *notificationQueue) write(buf []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return 0, unix.EBADF
	}
	return q.source.Write(buf)
}

// Watch changes and readiness polling share the same descriptor lifetime as reads.
func (q *notificationQueue) useDescriptor(fn func() (int, error)) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return 0, unix.EBADF
	}
	return fn()
}

func (q *notificationQueue) close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return q.closeErr
	}
	pending, err := q.source.Pending()
	if err != nil || pending < 0 {
		q.unavailable = true
	} else {
		q.unavailable = false
		// Events can still arrive before close. Retain only the known minimum.
		if q.variableRecords {
			// A byte count cannot identify the number of variable-length records.
			if pending > 0 {
				q.losses.Lose(time.Now(), 1)
			}
		} else {
			q.losses.Lose(time.Now(), uint64(pending))
		}
	}
	q.closeErr = q.source.Close()
	q.closed = true
	q.sampled.Observe(time.Now(), 0, q.consumed)
	return q.closeErr
}
