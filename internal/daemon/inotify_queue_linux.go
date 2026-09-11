//go:build linux

package daemon

import (
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type inotifyDescriptor struct{ fanotifyDescriptor }

func (fd inotifyDescriptor) Pending() (int, error) {
	return unix.IoctlGetInt(int(fd.fanotifyDescriptor), unix.TIOCINQ)
}

func newInotifyQueue(fd int) *notificationQueue {
	q := newNotificationQueue(inotifyDescriptor{fanotifyDescriptor(fd)}, queuehealth.New(0, time.Minute), queuehealth.New(1, time.Minute))
	q.sampled = queuehealth.NewSampled(0, "bytes", time.Minute)
	q.variableRecords = true
	return q
}

func (fw *ForwarderWatcher) initQueueHealth() {
	fw.queueHealthOnce.Do(func() { fw.kernelQueue = newInotifyQueue(fw.inotifyFd) })
}

func (fw *ForwarderWatcher) QueueStatuses(_ time.Time) map[string]queuehealth.Status {
	fw.initQueueHealth()
	kernel, reader := fw.kernelQueue.snapshot(time.Now)
	return map[string]queuehealth.Status{"kernel": kernel, "reader": reader}
}

func (w *spoolWatcher) initQueueHealth() {
	w.queueHealthOnce.Do(func() { w.kernelQueue = newInotifyQueue(w.fd) })
}

func (w *spoolWatcher) QueueStatuses(_ time.Time) map[string]queuehealth.Status {
	w.initQueueHealth()
	kernel, reader := w.kernelQueue.snapshot(time.Now)
	return map[string]queuehealth.Status{"kernel": kernel, "reader": reader}
}

// Set before publishing or running the replacement. Its descriptor has fresh
// occupancy, but a restart must not clear losses from this daemon's lifetime.
func (w *spoolWatcher) inheritQueueHealth(previous *spoolWatcher) {
	previous.initQueueHealth()
	w.initQueueHealth()
	w.kernelQueue.losses = previous.kernelQueue.losses
	w.kernelQueue.batches = previous.kernelQueue.batches
}
