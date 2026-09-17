package checks

import (
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

var wpCoreBatches = newScanBatchMonitor()

// WPCoreQueueStatus includes selected installations through checksum execution,
// result collection and verified-file caching. Concurrent scans share no cap.
func WPCoreQueueStatus(now time.Time) queuehealth.Status {
	status := wpCoreBatches.snapshot(now)
	status.DepthUnit = "installations"
	return status
}
