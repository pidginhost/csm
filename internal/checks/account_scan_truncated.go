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
	mu sync.Mutex
	// droppedBy is keyed by account scope so operators can see which
	// account tripped which cap. The empty-string key is the full-host
	// scan tier (no account scope on the context).
	droppedBy map[string]map[int]int
}

func withAccountScanTruncationCollector(ctx context.Context) (context.Context, *accountScanTruncationCollector) {
	if ctx == nil {
		ctx = context.Background()
	}
	collector := &accountScanTruncationCollector{droppedBy: map[string]map[int]int{}}
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
	collector.record(AccountFromContext(ctx), dropped, cap)
}

func (c *accountScanTruncationCollector) record(account string, dropped, cap int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	caps, ok := c.droppedBy[account]
	if !ok {
		caps = map[int]int{}
		c.droppedBy[account] = caps
	}
	caps[cap] += dropped
}

func (c *accountScanTruncationCollector) findings(now time.Time) []alert.Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.droppedBy) == 0 {
		return nil
	}
	accounts := make([]string, 0, len(c.droppedBy))
	for a := range c.droppedBy {
		accounts = append(accounts, a)
	}
	sort.Strings(accounts) // stable finding order across runs

	var findings []alert.Finding
	for _, account := range accounts {
		caps := c.droppedBy[account]
		capValues := make([]int, 0, len(caps))
		for cap := range caps {
			capValues = append(capValues, cap)
		}
		sort.Ints(capValues)
		for _, cap := range capValues {
			dropped := caps[cap]
			scope := "host scan"
			tenantID := ""
			if account != "" {
				scope = fmt.Sprintf("account %s", account)
				tenantID = account
			}
			findings = append(findings, alert.Finding{
				Severity:  alert.Warning,
				Check:     "account_scan_truncated",
				TenantID:  tenantID,
				Message:   fmt.Sprintf("Account scan truncated for %s: %d file(s) skipped past cap of %d", scope, dropped, cap),
				Details:   "Raise thresholds.account_scan_max_files if recent detection coverage matters more than scan duration.",
				Timestamp: now,
			})
		}
	}
	return findings
}
