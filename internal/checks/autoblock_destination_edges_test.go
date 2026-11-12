package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// A cached engine view deliberately has no LiveBlockedSet method.
// This is the same fallback used for saved operator and permanent blocks.
type c2CachedView struct{ IPBlocker }

func TestNetblockC2AddressValues(t *testing.T) {
	for _, tc := range []struct {
		name, ip, listed, cidr string
	}{
		{"mapped list", "198.51.100.10", "::ffff:198.51.100.10", "198.51.100.0/24"},
		{"mapped block", "::ffff:198.51.100.10", "198.51.100.10", "198.51.100.0/24"},
		{"IPv6 spelling", "2001:db8:1::10", "2001:0DB8:0001:0:0:0:0:10", "2001:db8:1::/64"},
	} {
		for _, mode := range []string{"ended history", "operator permanent fallback"} {
			for _, listed := range []bool{true, false} {
				name := tc.name + "/" + mode + "/empty list"
				if listed {
					name = tc.name + "/" + mode + "/listed"
				}
				t.Run(name, func(t *testing.T) {
					cfg := &config.Config{}
					if listed {
						cfg.C2Blocklist = []string{tc.listed}
					}
					now := time.Now()
					at := now.Add(-time.Minute)
					b := newNetblockBlocker()
					if mode == "operator permanent fallback" {
						b.live[tc.ip] = struct{}{}
						// An old permanent block still counts without the list.
						at = now.Add(-24 * time.Hour)
					}
					h := &netblockHistory{IPs: map[string]time.Time{tc.ip: at}}
					cached := c2CachedView{b}
					current := currentlyBlocked(nil, firewall.LiveBlockedSnapshot{}, false, h, cached)
					if current[tc.ip] != (mode == "operator permanent fallback") {
						t.Fatal("fixture did not exercise the cached membership fallback")
					}
					counts := netblockCounts(cfg, h, current, cached, now, time.Hour)
					if listed {
						if len(counts) != 0 {
							t.Fatalf("listed address counted: %v", counts)
						}
					} else if len(counts) != 1 || counts[tc.cidr] != 1 {
						t.Fatalf("empty list counts = %v, want exactly %s:1", counts, tc.cidr)
					}
				})
			}
		}
	}
}

// Exercise the common block implementation with alternate address spellings,
// including callers that bypass the scan's normalization.
func TestPermBlockC2AddressValues(t *testing.T) {
	for _, tc := range []struct{ name, ip, listed string }{
		{"mapped list", "198.51.100.10", "::ffff:198.51.100.10"},
		{"mapped request", "::ffff:198.51.100.10", "198.51.100.10"},
		{"IPv6 spelling", "2001:db8:1::10", "2001:0DB8:0001:0:0:0:0:10"},
	} {
		for _, listed := range []bool{true, false} {
			name := tc.name + "/empty list"
			if listed {
				name = tc.name + "/listed"
			}
			t.Run(name, func(t *testing.T) {
				cfg := pendingTestConfig(t)
				cfg.AutoResponse.PermBlock = true
				cfg.AutoResponse.PermBlockCount = 2
				cfg.AutoResponse.PermBlockInterval = "24h"
				if listed {
					cfg.C2Blocklist = []string{tc.listed}
				}
				earlier := time.Now().Add(-time.Hour)
				savePermBlockTracker(cfg.StatePath, &permBlockTracker{IPs: map[string][]time.Time{tc.ip: {earlier}}})
				b := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
				applyBlockTestSetup(t, b)
				res, err := applyBlockLocked(cfg, b, &blockState{}, ApplyBlockRequest{
					IP: tc.ip, TTL: time.Hour, Source: BlockSourceCentral,
					Reason: "confirmed local attacker", EngineReason: "CSM central-intel: local attacker",
				}, func() {}, func(error) {})
				if err != nil || res.Outcome != firewall.BlockOutcomeLive || len(b.calls) != 1 || b.calls[0].timeout != time.Hour {
					t.Fatalf("temporary block = %+v, %v, calls %+v", res, err, b.calls)
				}
				if listed {
					if len(b.promoted) != 0 {
						t.Fatalf("listed address promoted: %v", b.promoted)
					}
					if history := loadPermBlockTracker(cfg.StatePath).IPs[tc.ip]; len(history) != 1 || !history[0].Equal(earlier) {
						t.Fatalf("listed address changed permanent history: %v", history)
					}
				} else if len(b.promoted) != 1 || b.promoted[0] != tc.ip {
					t.Fatalf("empty list promotions = %v, want %s", b.promoted, tc.ip)
				}
			})
		}
	}
}
