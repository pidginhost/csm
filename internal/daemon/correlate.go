package daemon

import (
	"net"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// infraHostnames partitions the cfg.InfraIPs operator list into the
// subset that is hostnames (not literal IPs or CIDRs). Hostnames get
// DNS-refreshed into the engine's infra-block guard so operators can
// list panel hosts by name and have them stay protected as the
// underlying address rotates.
func infraHostnames(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		s := strings.TrimSpace(e)
		if s == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(s); err == nil {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			continue
		}
		out = append(out, s)
	}
	return out
}

// containsString returns true when s appears in haystack. Linear scan
// because the call site loops short DynDNS host lists where a map
// would not pay for itself.
func containsString(haystack []string, s string) bool {
	for _, h := range haystack {
		if h == s {
			return true
		}
	}
	return false
}

// expandWithCorrelation runs cross-account correlation over a dispatch
// batch and appends any synthesized findings that are not already present.
// The scan runner may have already produced the same synthetic findings, so
// this helper must be idempotent to avoid double-alerting the first batch.
func expandWithCorrelation(findings []alert.Finding, now time.Time) []alert.Finding {
	seen := make(map[string]struct{})
	for i := range findings {
		if !isCorrelationFinding(findings[i].Check) {
			continue
		}
		if findings[i].Timestamp.IsZero() {
			findings[i].Timestamp = now
		}
		seen[findings[i].Key()] = struct{}{}
	}

	extra := checks.CorrelateFindings(findings)
	for i := range extra {
		if extra[i].Timestamp.IsZero() {
			extra[i].Timestamp = now
		}
		key := extra[i].Key()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		findings = append(findings, extra[i])
	}
	return findings
}

func isCorrelationFinding(check string) bool {
	switch check {
	case "coordinated_attack", "cross_account_malware":
		return true
	default:
		return false
	}
}
