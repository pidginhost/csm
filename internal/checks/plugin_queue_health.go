package checks

import (
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

var pluginInventoryBatches = newScanBatchMonitor()

// PluginInventoryQueueStatus includes sites waiting for a worker and inventories
// still executing or committing their result. Concurrent refreshes share no cap.
func PluginInventoryQueueStatus(now time.Time) queuehealth.Status {
	return pluginInventoryBatches.snapshot(now)
}
