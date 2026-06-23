package daemon

import (
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

const (
	// modsecContextScanCap bounds the history walk per enriched IP. Denies that
	// drive one escalation number in the dozens, so a few thousand is ample
	// headroom while keeping the bbolt read cheap on a hammered host.
	modsecContextScanCap = 2000
	// modsecContextMaxItems caps the domains and URIs surfaced per block so the
	// digest line stays readable.
	modsecContextMaxItems = 5
)

// modsecEnricher returns the EnrichModSec lookup wired into the block digest.
// It reuses already-parsed modsec findings from the history store, so the
// digest can name targeted domains and request paths without re-reading the
// (multi-hundred-MB) audit log. The lookback matches the escalation window
// that produced the block.
func (d *Daemon) modsecEnricher(cfg *config.Config) func(ip string) (domains, uris []string) {
	_, win := modsecEscalationParams(cfg)
	return func(ip string) ([]string, []string) {
		return aggregateModSecContext(ip, time.Now().Add(-win))
	}
}

// aggregateModSecContext reads the per-deny modsec findings for one IP since the
// cutoff and returns its most-hit customer domains and request URIs. Escalation
// findings (no per-deny URI) and other IPs are skipped. Returns nil slices when
// no store is loaded or nothing matched.
func aggregateModSecContext(ip string, since time.Time) (domains, uris []string) {
	db := store.Global()
	if db == nil {
		return nil, nil
	}
	findings := db.SearchHistorySince(since, modsecContextScanCap, func(f alert.Finding) bool {
		return f.Check == "modsec_block_realtime" && f.SourceIP == ip
	})

	domainCounts := make(map[string]int)
	uriCounts := make(map[string]int)
	for _, f := range findings {
		if f.Domain != "" {
			domainCounts[f.Domain]++
		}
		if uri := modsecURIFromDetails(f.Details); uri != "" {
			uriCounts[uri]++
		}
	}
	return topByCount(domainCounts, modsecContextMaxItems), topByCount(uriCounts, modsecContextMaxItems)
}

// modsecURIFromDetails pulls the URI line out of a structured modsec finding
// Details blob ("Rule: ...\nURI: ...\n..."). Returns "" when absent.
func modsecURIFromDetails(details string) string {
	for _, line := range strings.Split(details, "\n") {
		if v, ok := strings.CutPrefix(line, "URI: "); ok {
			return v
		}
	}
	return ""
}

// topByCount returns up to n keys ordered by descending count, breaking ties on
// the key itself so output is deterministic. Returns nil when the map is empty.
func topByCount(counts map[string]int, n int) []string {
	if len(counts) == 0 {
		return nil
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	return keys
}
