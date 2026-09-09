package daemon

import (
	"fmt"
	"maps"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/queuehealth"
)

type queueSource interface {
	QueueStatuses(time.Time) map[string]queuehealth.Status
}

func (d *Daemon) registerBackendQueues(prefix string, backend bpf.Backend) {
	if source, ok := backend.(queueSource); ok {
		d.registerQueueSource(prefix, source)
	}
}

func (d *Daemon) registerQueueSource(prefix string, source queueSource) {
	d.queueSourcesMu.Lock()
	defer d.queueSourcesMu.Unlock()
	if d.queueSources == nil {
		d.queueSources = make(map[string]queueSource)
	}
	d.queueSources[prefix] = source
}

func (d *Daemon) registeredQueueStatuses(now time.Time) map[string]queuehealth.Status {
	d.queueSourcesMu.RLock()
	sources := maps.Clone(d.queueSources)
	d.queueSourcesMu.RUnlock()
	statuses := make(map[string]queuehealth.Status)
	for prefix, source := range sources {
		for name, status := range source.QueueStatuses(now) {
			statuses[prefix+"."+name] = status
		}
	}
	return statuses
}

func (d *Daemon) setFileMonitor(fm *FileMonitor) {
	d.fileMonitorMu.Lock()
	d.fileMonitor = fm
	d.fileMonitorMu.Unlock()
}

func (d *Daemon) getFileMonitor() *FileMonitor {
	d.fileMonitorMu.RLock()
	defer d.fileMonitorMu.RUnlock()
	return d.fileMonitor
}

func (d *Daemon) monitorQueueHealth() {
	defer d.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var reporter queuehealth.Reporter
	for {
		select {
		case <-d.stopCh:
			return
		case now := <-ticker.C:
			d.reportQueueHealth(now, &reporter)
		}
	}
}

func (d *Daemon) reportQueueHealth(now time.Time, reporter *queuehealth.Reporter) {
	events := reporter.Events(now, d.queueStatuses(now))
	if len(events) == 0 {
		return
	}
	findings := make([]alert.Finding, 0, len(events))
	for _, event := range events {
		check, message := "protection_queue_degraded", "Protection work is delayed or being dropped"
		if event.Recovered {
			check, message = "protection_queue_recovered", "Protection queue recovered"
		}
		s := event.Current
		findings = append(findings, alert.Finding{
			Check: check, Severity: alert.Warning, Message: message,
			DedupKey: event.Name, Timestamp: now,
			Details: fmt.Sprintf("queue=%s reason=%s %s", event.Name, s.Reason, s.Evidence()),
		})
	}
	// This loop owns delivery: the failing ingest channel cannot carry its
	// own alarm. History and passive observers receive transitions without
	// running automatic response or advancing the last completed scan time.
	d.store.AppendHistory(findings)
	if err := alert.Dispatch(d.currentCfg(), findings); err != nil {
		csmlog.Warn("queue health notification failed", "err", err)
	}
}
