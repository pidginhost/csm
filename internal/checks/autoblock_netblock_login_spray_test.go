package checks

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

// legacyRequestBlocker is an engine without durable actions that still
// takes full requests, as the real engine does.
type legacyRequestBlocker struct {
	outcomeStubBlocker
	requests []firewall.ActionRequest
	budgets  []*firewall.ScanAdmission
}

func (b *legacyRequestBlocker) DurableActionsEnabled() bool { return false }
func (b *legacyRequestBlocker) BlockIPRequest(req firewall.ActionRequest, budget *firewall.ScanAdmission) (firewall.BlockOutcome, error) {
	b.requests = append(b.requests, req)
	b.budgets = append(b.budgets, budget)
	return firewall.BlockOutcomeLive, nil
}

func trackerRows(state *blockState) map[string]blockedIP {
	rows := make(map[string]blockedIP, len(state.IPs))
	for _, row := range state.IPs {
		rows[row.IP] = row
	}
	return rows
}

// The spray flag reaches the engine on both paths and the tracker row keeps
// it; any other block carries none.
func TestApplyBlockPassesLoginSpray(t *testing.T) {
	const sprayIP, wafIP = "192.0.2.110", "198.51.100.110"
	spray := loginSprayFinding(sprayIP)

	t.Run("durable", func(t *testing.T) {
		cfg := pendingTestConfig(t)
		b := &scanAdmissionBlocker{outcomeStubBlocker: outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}}
		applyBlockTestSetup(t, b)
		AutoBlockIPs(cfg, []alert.Finding{spray, wafFinding(wafIP)})
		got := make(map[string]bool)
		for _, req := range b.requests {
			got[req.Target] = req.LoginSpray
		}
		if len(got) != 2 || !got[sprayIP] || got[wafIP] {
			t.Fatalf("durable requests = %+v, want the flag on the spray block only", b.requests)
		}
		rows := trackerRows(loadBlockState(cfg.StatePath))
		if len(rows) != 2 || !rows[sprayIP].LoginSpray || rows[wafIP].LoginSpray {
			t.Fatalf("tracker = %+v, want the flag on the spray row only", rows)
		}
	})

	t.Run("legacy", func(t *testing.T) {
		cfg := pendingTestConfig(t)
		b := &legacyRequestBlocker{outcomeStubBlocker: outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}}
		applyBlockTestSetup(t, b)
		AutoBlockIPs(cfg, []alert.Finding{spray, wafFinding(wafIP)})
		want := firewall.ActionRequest{
			Operation: "block", Target: sprayIP, Reason: "CSM auto-block: " + truncate(spray.Message, 100), TTL: loginSprayTTL,
			FindingID: alert.FindingID(spray), Automatic: true, Actor: "daemon", LoginSpray: true,
		}
		if len(b.requests) != 1 || b.requests[0] != want || b.budgets[0] != nil {
			t.Fatalf("requests = %+v, budgets = %v; want %+v without admission", b.requests, b.budgets, want)
		}
		if len(b.calls) != 1 || b.calls[0].ip != wafIP {
			t.Fatalf("plain calls = %+v, want the WAF block only", b.calls)
		}
		rows := trackerRows(loadBlockState(cfg.StatePath))
		if len(rows) != 2 || !rows[sprayIP].LoginSpray || rows[wafIP].LoginSpray {
			t.Fatalf("tracker = %+v, want the flag on the spray row only", rows)
		}
	})
}

// Spray blocks do not feed netblock escalation in either family; old-rule
// blocks still do, and history an address earned before its spray block
// still counts within the window.
func TestNetblockIgnoresLoginSprayBlocks(t *testing.T) {
	addresses := []string{"198.51.100.10", "198.51.100.20", "198.51.100.30", "2001:db8:1::10", "2001:db8:1::20", "2001:db8:1::30"}
	run := func(t *testing.T, finding func(string) alert.Finding) []string {
		t.Helper()
		cfg := netblockWindowConfig(t)
		blocker := newNetblockBlocker()
		swapBlocker(t, blocker)
		var findings []alert.Finding
		for _, ip := range addresses {
			findings = append(findings, finding(ip))
		}
		AutoBlockIPs(cfg, findings)
		if len(blocker.live) != len(addresses) {
			t.Fatalf("blocked = %v, want every address", blocker.live)
		}
		// The next cycle sees these blocks in the live set as well.
		AutoBlockIPs(cfg, nil)
		return blocker.subnets
	}

	t.Run("spray blocks", func(t *testing.T) {
		if subnets := run(t, loginSprayFinding); len(subnets) != 0 {
			t.Fatalf("subnets = %v, want none from spray blocks", subnets)
		}
	})
	t.Run("old-rule blocks", func(t *testing.T) {
		subnets := run(t, perIPMailFinding)
		if len(subnets) != 2 || !contains(subnets, "198.51.100.0/24") || !contains(subnets, "2001:db8:1::/64") {
			t.Fatalf("subnets = %v, want the /24 and the /64", subnets)
		}
	})
	// Without a live listing the history fallback asks the blocker per
	// address; a spray block must not count there either.
	for _, listed := range []bool{true, false} {
		t.Run(fmt.Sprintf("earlier history listed=%t", listed), func(t *testing.T) {
			cfg := netblockWindowConfig(t)
			now := time.Now()
			setAutoBlockNow(t, now)
			mustSaveNetblockHistory(t, cfg.StatePath, &netblockHistory{IPs: map[string]time.Time{
				"203.0.113.10": now.Add(-time.Hour),
				"203.0.113.20": now.Add(-8 * 24 * time.Hour),
				"203.0.113.30": now.Add(-8 * 24 * time.Hour),
			}})
			blocker := newNetblockBlocker()
			if listed {
				swapBlocker(t, blocker)
			} else {
				swapBlocker(t, unlistedNetblockBlocker{blocker})
			}

			AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("203.0.113.10"), loginSprayFinding("203.0.113.20"), loginSprayFinding("203.0.113.30")})
			if len(blocker.live) != 3 || len(blocker.subnets) != 0 {
				t.Fatalf("blocked = %v, subnets = %v; want three spray blocks and no subnet", blocker.live, blocker.subnets)
			}
			AutoBlockIPs(cfg, []alert.Finding{perIPMailFinding("203.0.113.40"), perIPMailFinding("203.0.113.50")})
			if len(blocker.subnets) != 1 || blocker.subnets[0] != "203.0.113.0/24" {
				t.Fatalf("subnets = %v, want the /24 from the earlier offender and two old-rule blocks", blocker.subnets)
			}
		})
	}
}

// unlistedNetblockBlocker is a netblockBlocker that cannot list its live set.
type unlistedNetblockBlocker struct{ b *netblockBlocker }

func (u unlistedNetblockBlocker) BlockIP(ip, reason string, ttl time.Duration) error {
	return u.b.BlockIP(ip, reason, ttl)
}
func (u unlistedNetblockBlocker) UnblockIP(ip string) error { return u.b.UnblockIP(ip) }
func (u unlistedNetblockBlocker) IsBlocked(ip string) bool  { return u.b.IsBlocked(ip) }
func (u unlistedNetblockBlocker) BlockSubnet(cidr, reason string, ttl time.Duration) error {
	return u.b.BlockSubnet(cidr, reason, ttl)
}
func (u unlistedNetblockBlocker) IsSubnetBlocked(cidr string) bool { return u.b.IsSubnetBlocked(cidr) }
func (u unlistedNetblockBlocker) IsAllowed(ip string) bool         { return u.b.IsAllowed(ip) }

// A netblock names the newest block that counted toward it, never a newer
// spray block in the same subnet: spray blocks are not its evidence.
func TestNetblockCauseSkipsLoginSprayRows(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.NetBlock = true
	cfg.AutoResponse.NetBlockThreshold = 3
	b := &findingIDBlocker{outcomeStubBlocker: outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}, live: make(map[string]bool)}
	applyBlockTestSetup(t, b)
	now := time.Now()
	seed := &blockState{}
	for i, id := range []string{"old-rule-1", "old-rule-2", "old-rule-3"} {
		ip := fmt.Sprintf("198.51.100.%d", 10*(i+1))
		seed.IPs = append(seed.IPs, blockedIP{IP: ip, FindingID: id, BlockedAt: now.Add(time.Duration(i-10) * time.Minute), ExpiresAt: now.Add(time.Hour)})
		b.live[ip] = true
	}
	seed.IPs = append(seed.IPs, blockedIP{IP: "198.51.100.40", FindingID: "spray", BlockedAt: now, ExpiresAt: now.Add(loginSprayTTL), LoginSpray: true})
	b.live["198.51.100.40"] = true
	saveBlockState(cfg.StatePath, seed)

	AutoBlockIPs(cfg, nil)
	if len(b.subnetIDs) != 1 || b.subnetIDs[0] != "old-rule-3" {
		t.Fatalf("netblock IDs = %q, want the newest non-spray block old-rule-3", b.subnetIDs)
	}
}
