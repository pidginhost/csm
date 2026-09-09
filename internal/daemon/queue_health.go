package daemon

import (
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/queuehealth"
)

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
			Details: fmt.Sprintf("queue=%s reason=%s depth=%d/%d running=%d dropped=%d recent_drops=%d lag=%.0fs processing=%.0fs",
				event.Name, s.Reason, s.Depth, s.Capacity, s.InFlight,
				s.DroppedTotal, s.RecentDrops, s.LagSeconds, s.ProcessingSeconds),
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
