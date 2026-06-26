package mailranges

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/atomicio"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/metrics"
)

// Providers maps provider name to the SPF root domain that covers all
// outbound mail ranges for that provider. Only the two major mail providers
// whose shared IPs are relevant for DoS-exempt range building are included.
// No JSON feed URLs, ASN feeds, or CIDR lists; only SPF root domains.
var Providers = map[string]string{
	"google":    "_spf.google.com",
	"microsoft": "spf.protection.outlook.com",
}

// staleCacheThreshold is how old the last-good cache must be before a failed
// refresh emits a warning so operators know the data may be outdated.
const staleCacheThreshold = 7 * 24 * time.Hour

// Package-level atomics for metrics. Separate from providerAtom and
// lastRefreshAt (defined in mailranges.go) to keep each concern isolated.
var (
	mailrangesRefreshTotal atomic.Uint64 // number of refreshes with >= 1 success
	mailrangesPrefixes     atomic.Int64  // total prefix count after last successful refresh
	staleCacheWarnings     atomic.Uint64 // stale-cache warnings emitted (test-observable)
)

// RegisterMailrangesMetrics binds the mailranges counters and gauges to reg.
// Production callers pass metrics.Default(); tests pass metrics.NewRegistry()
// to keep registration isolated. Idempotent per-registry (the underlying
// RegisterCounterFunc/RegisterGaugeFunc panic on duplicate names; callers
// must not register the same registry twice).
func RegisterMailrangesMetrics(reg *metrics.Registry) {
	reg.RegisterCounterFunc(
		"csm_mailranges_refresh_total",
		"Total provider range refreshes with at least one successful SPF resolve.",
		func() float64 { return float64(mailrangesRefreshTotal.Load()) },
	)
	reg.RegisterGaugeFunc(
		"csm_mailranges_prefixes",
		"Current number of mail-provider prefixes across all providers.",
		func() float64 { return float64(mailrangesPrefixes.Load()) },
	)
	reg.RegisterGaugeFunc(
		"csm_mailranges_last_success_timestamp_seconds",
		"Unix timestamp of the last successful provider range refresh.",
		func() float64 { return float64(lastRefreshAt.Load()) },
	)
}

// Refresh resolves every provider in Providers using r. For each provider that
// fails, the provider's previous last-good ranges are kept in the merged map.
// When at least one provider resolves successfully, the merged map is serialized
// and written atomically to cachePath, then published as the active snapshot and
// metrics are updated. The active snapshot is only updated after the write
// succeeds so a torn write cannot narrow the effective set.
//
// Returns (total prefixes across the merged map, nil) on full success.
// Returns (total, joinedErr) when some providers fail but at least one
// succeeds, where joinedErr wraps every failed provider's error.
// Returns (0, joinedErr) when all providers fail or the cache cannot be
// written; in the all-failure case, if the existing cache is older than 7 days,
// a stale-cache warning is emitted.
func Refresh(ctx context.Context, r Resolver, cachePath string) (int, error) {
	// Take a snapshot of the current active provider map to use as the
	// last-good baseline. Providers that fail this cycle keep their entry.
	prev := ProviderSnapshot()

	// Prime the merged map with last-good values. Successful resolves overwrite.
	merged := make(map[string][]*net.IPNet, len(Providers))
	for name := range Providers {
		if nets, ok := prev[name]; ok {
			merged[name] = nets
		}
	}

	var errs []error
	successCount := 0
	for name, root := range Providers {
		nets, err := ResolveSPF(ctx, r, root)
		if err != nil {
			csmlog.Warn("mailranges: provider SPF resolve failed",
				"provider", name, "root", root, "err", err)
			errs = append(errs, fmt.Errorf("provider %q: %w", name, err))
			continue
		}
		merged[name] = nets
		successCount++
	}

	// All providers failed: do not write or publish; warn if the cache is stale.
	if successCount == 0 {
		ts := lastRefreshAt.Load()
		if ts != 0 && time.Since(time.Unix(ts, 0)) > staleCacheThreshold {
			staleCacheWarnings.Add(1)
			csmlog.Warn("mailranges: provider refresh failed; cache is stale",
				"age_hours", int(time.Since(time.Unix(ts, 0)).Hours()))
		}
		return 0, errors.Join(errs...)
	}

	// Count total prefixes across all merged providers (successful + last-good).
	total := 0
	for _, nets := range merged {
		total += len(nets)
	}

	// Build the on-disk cache payload. Sort each provider's slice for stable output.
	cf := cacheFile{
		RefreshedAt: time.Now().Unix(),
		Providers:   make(map[string][]string, len(merged)),
	}
	for name, nets := range merged {
		strs := make([]string, 0, len(nets))
		for _, n := range nets {
			strs = append(strs, n.String())
		}
		sort.Strings(strs)
		cf.Providers[name] = strs
	}

	data, err := json.Marshal(cf)
	if err != nil {
		return 0, err
	}

	// Atomic write first. Do not touch the active snapshot if the write fails.
	if err := atomicio.AtomicWrite(cachePath, 0o600, data); err != nil {
		return 0, err
	}

	// Publish only after the write commits.
	PublishProviderSnapshot(merged)
	lastRefreshAt.Store(cf.RefreshedAt)

	// Update metrics only when at least one provider resolved successfully.
	mailrangesRefreshTotal.Add(1)
	mailrangesPrefixes.Store(int64(total))

	// errs is non-nil only on partial failure; errors.Join(nil...) returns nil
	// for the full-success path.
	return total, errors.Join(errs...)
}
