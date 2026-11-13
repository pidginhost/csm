package checks

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

func c2Finding(ip string) alert.Finding {
	return alert.Finding{Severity: alert.Critical, Check: "c2_connection", SourceIP: ip, Message: "Connection to known C2 IP: " + ip + ":443", Timestamp: time.Now()}
}

var c2ListedAddresses = []string{"198.51.100.10", "198.51.100.20", "198.51.100.30", "2001:db8:1::10", "2001:db8:1::20", "2001:db8:1::30"}

// An address on c2_blocklist is where local processes connect, not a source
// of attacks: its blocks never count toward a subnet block in either
// family, whatever finding asked for them, and from the tracker or only
// from the kernel's set. Other addresses in the subnet still count.
func TestNetblockIgnoresC2ListedAddresses(t *testing.T) {
	unlisted := func(n int) []string {
		var out []string
		for i := 1; i <= n; i++ {
			out = append(out, fmt.Sprintf("198.51.100.%d", 100+i), fmt.Sprintf("2001:db8:1::%d", 100+i))
		}
		return out
	}
	each := func(make func(string) alert.Finding, ips []string) []alert.Finding {
		var out []alert.Finding
		for _, ip := range ips {
			out = append(out, make(ip))
		}
		return out
	}
	for _, tc := range []struct {
		name        string
		findings    []alert.Finding
		kernelOnly  bool
		wantSubnets int
	}{
		{"C2 connections", each(c2Finding, c2ListedAddresses), false, 0},
		{"listed attackers", each(perIPMailFinding, c2ListedAddresses), false, 0},
		{"two unlisted neighbours", append(each(c2Finding, c2ListedAddresses), each(perIPMailFinding, unlisted(2))...), false, 0},
		{"three unlisted neighbours", append(each(c2Finding, c2ListedAddresses), each(perIPMailFinding, unlisted(3))...), false, 2},
		{"listed in the kernel set only", each(perIPMailFinding, unlisted(2)), true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := netblockWindowConfig(t)
			// The list matches addresses, not their spelling.
			cfg.C2Blocklist = []string{"198.51.100.10", "198.51.100.20", "198.51.100.30", "2001:DB8:1::10", "2001:db8:1:0::20", "2001:0db8:1::30"}
			blocker := newNetblockBlocker()
			if tc.kernelOnly {
				for _, ip := range c2ListedAddresses {
					blocker.live[ip] = struct{}{}
				}
			}
			swapBlocker(t, blocker)
			AutoBlockIPs(cfg, tc.findings)
			AutoBlockIPs(cfg, nil)
			if len(blocker.subnets) != tc.wantSubnets {
				t.Fatalf("subnets = %v, want %d", blocker.subnets, tc.wantSubnets)
			}
			if tc.wantSubnets == 2 && (!contains(blocker.subnets, "198.51.100.0/24") || !contains(blocker.subnets, "2001:db8:1::/64")) {
				t.Fatalf("subnets = %v, want the /24 and the /64", blocker.subnets)
			}
		})
	}
}

// A subnet block names the newest block that counted toward it, never a
// newer block of a listed C2 server in the same subnet.
func TestNetblockCauseSkipsC2ListedRows(t *testing.T) {
	for _, tc := range []struct{ name, listed, want string }{
		{"canonical", "198.51.100.40", "attacker-3"},
		{"mapped", "::ffff:198.51.100.40", "attacker-3"},
		{"empty list", "", "c2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.NetBlock = true
			cfg.AutoResponse.NetBlockThreshold = 3
			if tc.listed != "" {
				cfg.C2Blocklist = []string{tc.listed}
			}
			b := &findingIDBlocker{outcomeStubBlocker: outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}, live: make(map[string]bool)}
			applyBlockTestSetup(t, b)
			now := time.Now()
			seed := &blockState{}
			for i, id := range []string{"attacker-1", "attacker-2", "attacker-3"} {
				ip := fmt.Sprintf("198.51.100.%d", 10*(i+1))
				seed.IPs = append(seed.IPs, blockedIP{IP: ip, FindingID: id, BlockedAt: now.Add(time.Duration(i-10) * time.Minute), ExpiresAt: now.Add(time.Hour)})
				b.live[ip] = true
			}
			seed.IPs = append(seed.IPs, blockedIP{IP: "198.51.100.40", FindingID: "c2", BlockedAt: now, ExpiresAt: now.Add(time.Hour)})
			b.live["198.51.100.40"] = true
			saveBlockState(cfg.StatePath, seed)

			AutoBlockIPs(cfg, nil)
			if len(b.subnetIDs) != 1 || b.subnetIDs[0] != tc.want {
				t.Fatalf("netblock IDs = %q, want the newest eligible block %s", b.subnetIDs, tc.want)
			}
		})
	}
}

// Blocks of an address on c2_blocklist never promote it to a permanent
// block and never add to its count, whatever finding asked for them.
func TestPermBlockIgnoresC2ListedAddresses(t *testing.T) {
	for _, finding := range []alert.Finding{c2Finding("203.0.113.9"), wafFinding("203.0.113.9")} {
		t.Run(finding.Check, func(t *testing.T) {
			cfg := &config.Config{C2Blocklist: []string{"203.0.113.9"}}
			cfg.StatePath = t.TempDir()
			cfg.AutoResponse.Enabled = true
			cfg.AutoResponse.BlockIPs = true
			cfg.AutoResponse.BlockExpiry = "1h"
			cfg.AutoResponse.PermBlock = true
			cfg.AutoResponse.PermBlockCount = 2
			cfg.AutoResponse.PermBlockInterval = "24h"
			setAutoResponseLive(cfg)
			earlier := time.Now().Add(-time.Hour)
			savePermBlockTracker(cfg.StatePath, &permBlockTracker{IPs: map[string][]time.Time{"203.0.113.9": {earlier}}})
			blocker := &recordingIPBlocker{}
			oldBlocker := getIPBlocker()
			SetIPBlocker(blocker)
			t.Cleanup(func() { SetIPBlocker(oldBlocker) })
			oldChallengeList := GetChallengeIPList()
			SetChallengeIPList(nil)
			t.Cleanup(func() { SetChallengeIPList(oldChallengeList) })

			actions := AutoBlockIPs(cfg, []alert.Finding{finding})
			if len(blocker.calls) != 1 || blocker.calls[0].timeout != time.Hour {
				t.Fatalf("block calls = %+v, want one temporary block", blocker.calls)
			}
			for _, a := range actions {
				if strings.Contains(a.Message, "AUTO-PERMBLOCK") {
					t.Fatalf("actions = %+v, want no permanent promotion", actions)
				}
			}
			if got := loadPermBlockTracker(cfg.StatePath).IPs["203.0.113.9"]; len(got) != 1 || !got[0].Equal(earlier) {
				t.Fatalf("permblock history = %v, want only the earlier block", got)
			}
		})
	}
}
