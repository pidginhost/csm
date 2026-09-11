//go:build linux

package daemon

import (
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

func (fm *FileMonitor) initQueueHealth() {
	fm.queueHealthOnce.Do(func() {
		fm.analyzerHealth = queuehealth.New(cap(fm.analyzerCh), time.Minute)
		fm.reconcileHealth = queuehealth.New(reconcileDirCap, time.Minute)
		fm.kernelQueueHealth = queuehealth.New(0, time.Minute)
		fm.kernelQueue = newNotificationQueue(fanotifyDescriptor(fm.fd), fm.kernelQueueHealth, queuehealth.New(1, time.Minute))
	})
}

func (fm *FileMonitor) queueStatuses(now time.Time) map[string]queuehealth.Status {
	fm.initQueueHealth()
	kernel, reader := fm.kernelQueue.snapshot(time.Now)
	reconcile := fm.reconcileHealth.Snapshot(now)
	reconcile.DepthUnit = "directories"
	statuses := map[string]queuehealth.Status{
		"fanotify.analyzer":        fm.analyzerHealth.Snapshot(now),
		"fanotify.kernel":          kernel,
		"fanotify.reader":          reader,
		"fanotify.reconcile":       reconcile,
		"fanotify.staged_packages": fm.stagedPackages().snapshot(now),
	}
	if fm.dropper != nil {
		statuses["fanotify.dropper"], statuses["fanotify.dropper_findings"] = fm.dropper.tr.queueStatuses(now)
	}
	return statuses
}

func (sw *SpoolWatcher) initQueueHealth() {
	sw.queueHealthOnce.Do(func() {
		sw.scannerHealth = queuehealth.New(cap(sw.scanCh), time.Minute)
		sw.kernelQueueHealth = queuehealth.New(0, time.Minute)
		sw.kernelQueue = newNotificationQueue(fanotifyDescriptor(sw.fd), sw.kernelQueueHealth, queuehealth.New(1, time.Minute))
	})
}

// A restarted watcher belongs to the same daemon lifetime. Carry its work
// accounting forward so repeated crashes cannot clear the recent loss window.
func (sw *SpoolWatcher) inheritQueueHealth(previous *SpoolWatcher) {
	previous.initQueueHealth()
	sw.queueHealthOnce.Do(func() {
		sw.scannerHealth = previous.scannerHealth
		sw.kernelQueueHealth = previous.kernelQueueHealth
		sw.kernelQueue = newNotificationQueue(fanotifyDescriptor(sw.fd), sw.kernelQueueHealth, previous.kernelQueue.batches)
	})
}

func (sw *SpoolWatcher) queueStatuses(now time.Time) map[string]queuehealth.Status {
	sw.initQueueHealth()
	kernel, reader := sw.kernelQueue.snapshot(time.Now)
	return map[string]queuehealth.Status{
		"spool.scanner": sw.scannerHealth.Snapshot(now),
		"spool.kernel":  kernel,
		"spool.reader":  reader,
	}
}
