package checks

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

type accountScanTruncationContextKey struct{}

type accountScanTruncationCollector struct {
	mu           sync.Mutex
	droppedByCap map[int]int
}

func withAccountScanTruncationCollector(ctx context.Context) (context.Context, *accountScanTruncationCollector) {
	if ctx == nil {
		ctx = context.Background()
	}
	collector := &accountScanTruncationCollector{droppedByCap: map[int]int{}}
	return context.WithValue(ctx, accountScanTruncationContextKey{}, collector), collector
}

func recordAccountScanTruncated(ctx context.Context, dropped, cap int) {
	if dropped <= 0 || cap <= 0 || ctx == nil {
		return
	}
	collector, ok := ctx.Value(accountScanTruncationContextKey{}).(*accountScanTruncationCollector)
	if !ok || collector == nil {
		return
	}
	collector.record(dropped, cap)
}

func (c *accountScanTruncationCollector) record(dropped, cap int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.droppedByCap[cap] += dropped
}

func (c *accountScanTruncationCollector) findings(now time.Time) []alert.Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.droppedByCap) == 0 {
		return nil
	}
	caps := make([]int, 0, len(c.droppedByCap))
	for cap := range c.droppedByCap {
		caps = append(caps, cap)
	}
	sort.Ints(caps)

	findings := make([]alert.Finding, 0, len(caps))
	for _, cap := range caps {
		dropped := c.droppedByCap[cap]
		findings = append(findings, alert.Finding{
			Severity:  alert.Warning,
			Check:     "account_scan_truncated",
			Message:   fmt.Sprintf("Account scan truncated: %d file(s) skipped past cap of %d", dropped, cap),
			Details:   "Raise thresholds.account_scan_max_files if recent detection coverage matters more than scan duration.",
			Timestamp: now,
		})
	}
	return findings
}
