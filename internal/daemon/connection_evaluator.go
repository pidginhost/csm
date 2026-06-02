package daemon

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

var (
	directSMTPRDNSOnce  sync.Once
	directSMTPRDNSCache *checks.RDNSCache
)

// rdnsCache is the daemon-wide rDNS cache used by direct SMTP egress
// detection. TTL 30 min, per-lookup deadline 1 second. Resolver wraps
// net.LookupAddr; negative results cached so a slow upstream does not
// stall the connection consumer.
func rdnsCache() *checks.RDNSCache {
	directSMTPRDNSOnce.Do(func() {
		directSMTPRDNSCache = checks.NewRDNSCache(checks.RDNSCacheConfig{
			TTL:             30 * time.Minute,
			ResolveDeadline: time.Second,
			Resolve: func(ip net.IP) (string, error) {
				names, err := net.LookupAddr(ip.String())
				if err != nil || len(names) == 0 {
					return "", err
				}
				return strings.TrimSuffix(names[0], "."), nil
			},
		})
	})
	return directSMTPRDNSCache
}

// evaluateConnectionEvent runs every per-event detector and returns the
// findings that should be emitted. Pure-ish: no IO and no alertCh
// access. Caller is responsible for attaching process context (which
// MAY do IO via the enricher) and shipping to alertCh.
//
// The function exists in a non-build-tagged file so unit tests can
// drive a synthetic ConnectionEvent through the same policy logic the
// live BPF Run loop uses, without requiring the linux+bpf build tag.
func evaluateConnectionEvent(cfg *config.Config, mta platform.MTAIdents, ev ConnectionEvent, user string) []alert.Finding {
	switch ev.Decision {
	case 0:
		BumpBPFEnforcementDecision(BPFDecisionAllow)
	case 1:
		BumpBPFEnforcementDecision(BPFDecisionDryRun)
	case 2:
		BumpBPFEnforcementDecision(BPFDecisionDeny)
	}

	// Phase 4 note: bpf_enforcement.verdict_callback is applied by the
	// BPF Run loop after this evaluator returns. The in-kernel hook
	// NEVER waits on HTTP; cgroup/connect is synchronous and a remote
	// callback would add latency to every connect.

	now := time.Now()

	// Phase 3 note: DryRun knobs are not consulted here. Detection runs
	// regardless. The knobs gate the Phase 4 auto-response action that
	// has not landed yet.
	var out []alert.Finding

	if checks.DirectSMTPEgressBackendEnabled(cfg, "bpf") {
		// Direct SMTP egress (Phase 3). Distinct Check value; the inbound
		// smtp_probe meters never see this traffic.
		if f, ok := checks.EvaluateDirectSMTPEgress(cfg, checks.DirectSMTPEgressInput{
			UID:     ev.UID,
			User:    user,
			PID:     ev.PID,
			Comm:    ev.Comm,
			DstIP:   ev.DstIP,
			DstPort: ev.DstPort,
			MTA:     mta,
		}); ok {
			if domain := rdnsCache().Lookup(ev.DstIP); domain != "" {
				f.Details += ", Domain: " + domain
			}
			f.Timestamp = now
			out = append(out, f)
			checks.BumpDirectSMTPEgressFindings()
		}
	}

	// Pre-existing user_outbound_connection detector. SMTP destinations
	// are filtered out by checks.safeRemotePorts inside this evaluator,
	// so it does not double-fire for a 25/465/587 connect.
	if f, ok := checks.EvaluateConnection(cfg, ev.UID, ev.DstIP, ev.DstPort, 0, protoFromFamily(ev.Family), user); ok {
		f.Timestamp = now
		out = append(out, f)
	}

	// Bad-ASN egress (host-takeover chain leg). Unlike user_outbound this is
	// evaluated for every UID including root, so live exfil from a post-exploit
	// root process is caught -- the periodic /proc/net poll skips root rows.
	if lookup := checks.CurrentASNLookup(); lookup != nil && cfg.Detection.BadASNOutbound.Enabled {
		asn, org := lookup(ev.DstIP.String())
		if f, ok := checks.EvaluateBadASNOutbound(cfg, ev.DstIP, asn, org); ok {
			f.Timestamp = now
			out = append(out, f)
		}
	}
	return out
}

// protoFromFamily maps a sockaddr family int to a string label used in
// finding details. Lives here (not in connection_bpf.go) so the
// evaluator helper compiles on darwin without the bpf tag.
func protoFromFamily(f uint32) string {
	if f == 10 {
		return "tcp6"
	}
	return "tcp"
}
