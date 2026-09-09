//go:build linux

package daemon

import (
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

func (fm *FileMonitor) initQueueHealth() {
	fm.queueHealthOnce.Do(func() {
		fm.analyzerHealth = queuehealth.New(cap(fm.analyzerCh), time.Minute)
		fm.kernelQueueHealth = queuehealth.New(0, time.Minute)
	})
}

func (fm *FileMonitor) queueStatuses(now time.Time) map[string]queuehealth.Status {
	fm.initQueueHealth()
	statuses := map[string]queuehealth.Status{
		"fanotify.analyzer":        fm.analyzerHealth.Snapshot(now),
		"fanotify.kernel":          fm.kernelQueueHealth.Snapshot(now),
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
	})
}

// A restarted watcher belongs to the same daemon lifetime. Carry its work
// accounting forward so repeated crashes cannot clear the recent loss window.
func (sw *SpoolWatcher) inheritQueueHealth(previous *SpoolWatcher) {
	previous.initQueueHealth()
	sw.queueHealthOnce.Do(func() {
		sw.scannerHealth = previous.scannerHealth
		sw.kernelQueueHealth = previous.kernelQueueHealth
	})
}

func (sw *SpoolWatcher) queueStatuses(now time.Time) map[string]queuehealth.Status {
	sw.initQueueHealth()
	return map[string]queuehealth.Status{
		"spool.scanner": sw.scannerHealth.Snapshot(now),
		"spool.kernel":  sw.kernelQueueHealth.Snapshot(now),
	}
}
