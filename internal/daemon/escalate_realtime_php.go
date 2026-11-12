package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

var escalateRealtimePHP = checks.EscalateRealtimePHP

// A completed analysis can arrive beside a scheduled response for the same
// path. Preserve that response's provenance even when dedup keeps our result.
func preserveEscalationResponseProvenance(findings []alert.Finding) {
	evaluated := make(map[string]bool)
	for _, f := range findings {
		if f.AutoFileResponseEvaluated && f.FilePath != "" {
			evaluated[filepath.Clean(f.FilePath)] = true
		}
	}
	for i, f := range findings {
		if f.FileResponseIdentity != "" && evaluated[filepath.Clean(f.FilePath)] {
			findings[i].AutoFileResponseEvaluated = true
		}
	}
}

// The queue has the same bound as alert intake. A single worker keeps slow
// regular-file reads out of dispatch without spawning unbounded readers.
func (d *Daemon) queuePHPEscalations(findings []alert.Finding) {
	for _, f := range findings {
		select {
		case <-d.stopCh:
			return
		default:
		}
		select {
		case d.phpEscalations <- f:
		default:
			atomic.AddInt64(&d.droppedAlerts, 1)
			fmt.Fprintf(os.Stderr, "[%s] PHP escalation queue full; original alert retained\n", ts())
		}
	}
}

func (d *Daemon) phpEscalationWorker() {
	defer d.wg.Done()
	for {
		select {
		case <-d.stopCh:
			return
		case f := <-d.phpEscalations:
			select {
			case <-d.stopCh:
				return
			default:
			}
			if d.store.IsSuppressed(f, d.store.LoadSuppressions()) {
				continue
			}
			findings := escalateRealtimePHP(d.currentCfg(), []alert.Finding{f})
			// Returning through intake gives results normal timestamps, state
			// deduplication, history, suppression and incident correlation.
			d.enqueueScanAlerts(findings, "PHP escalation")
		}
	}
}
