package checks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

type taggedNetblockBlocker struct {
	*netblockBlocker
	rows []firewall.BlockedEntry
	err  error
}

func (b *taggedNetblockBlocker) BlockedEntries() ([]firewall.BlockedEntry, error) {
	return b.rows, b.err
}

func TestNetblockUsesFirewallSprayTags(t *testing.T) {
	for _, mode := range []string{"missing tracker", "unreadable tracker", "untagged tracker", "operator replacement", "metadata unavailable", "absent kernel rows"} {
		t.Run(mode, func(t *testing.T) {
			cfg := netblockWindowConfig(t)
			b := &taggedNetblockBlocker{netblockBlocker: newNetblockBlocker()}
			swapBlocker(t, b)
			now := time.Now()
			tracker := &blockState{}
			for _, ip := range []string{"192.0.2.10", "192.0.2.20", "192.0.2.30", "2001:db8:1::10", "2001:db8:1::20", "2001:db8:1::30"} {
				if mode != "absent kernel rows" {
					b.live[ip] = struct{}{}
				}
				b.rows = append(b.rows, firewall.BlockedEntry{IP: ip, BlockedAt: now, ExpiresAt: now.Add(time.Hour), Automatic: true, LoginSpray: mode != "operator replacement"})
				if mode == "untagged tracker" || mode == "operator replacement" {
					tracker.IPs = append(tracker.IPs, blockedIP{IP: ip, FindingID: "old-finding", BlockedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), LoginSpray: mode == "operator replacement"})
				}
			}
			if mode == "metadata unavailable" {
				b.err = errors.New("block metadata unavailable")
			}
			if mode == "unreadable tracker" {
				if err := os.WriteFile(filepath.Join(cfg.StatePath, "blocked_ips.json"), []byte("invalid JSON"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if len(tracker.IPs) != 0 {
				saveBlockState(cfg.StatePath, tracker)
			}
			AutoBlockIPs(cfg, nil)
			history, err := loadNetblockHistory(cfg.StatePath)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "operator replacement":
				if len(b.subnets) != 2 || !contains(b.subnets, "192.0.2.0/24") || !contains(b.subnets, "2001:db8:1::/64") || len(history.IPs) != 6 {
					t.Fatalf("operator blocks inherited spray exemption: subnets=%v, history=%v", b.subnets, history.IPs)
				}
			case "metadata unavailable", "absent kernel rows":
				if len(b.subnets) != 0 || len(history.IPs) != 0 {
					t.Fatalf("unknown or absent blocks became range evidence: subnets=%v, history=%v", b.subnets, history.IPs)
				}
			default:
				// IPv4 spray blocks are never range evidence; IPv6 ones count
				// toward their /64.
				_, v4 := history.IPs["192.0.2.10"]
				if len(b.subnets) != 1 || b.subnets[0] != "2001:db8:1::/64" || len(history.IPs) != 3 || v4 {
					t.Fatalf("spray tags misclassified: subnets=%v, history=%v", b.subnets, history.IPs)
				}
			}
		})
	}
}

func TestNetblockUntrackedOperatorKeepsObservedHistory(t *testing.T) {
	cfg := netblockWindowConfig(t)
	now := time.Now()
	setAutoBlockNow(t, now)
	const ip = "192.0.2.50"
	b := &taggedNetblockBlocker{netblockBlocker: newNetblockBlocker(), rows: []firewall.BlockedEntry{{IP: ip, BlockedAt: now.Add(-8 * 24 * time.Hour)}}}
	b.live[ip] = struct{}{}
	swapBlocker(t, b)
	AutoBlockIPs(cfg, nil)
	h, err := loadNetblockHistory(cfg.StatePath)
	if err != nil || !h.IPs[ip].Equal(now) {
		t.Fatalf("untracked operator history must start when observed: %+v, %v", h, err)
	}
}

// Kernel membership wins over a stale cache. If that family could not be
// read, retain the cache's answer instead of guessing that a block ended.
func TestNetblockSprayMetadataRequiresMembership(t *testing.T) {
	const ip = "2001:db8:1::10"
	for _, tc := range []struct {
		name                    string
		listed, covered, cached bool
		want                    int
	}{
		{"absent despite cache", true, true, true, 0},
		{"uncovered with cache", true, false, true, 1},
		{"uncovered without cache", true, false, false, 0},
		{"unlisted with cache", false, false, true, 1},
		{"unlisted without cache", false, false, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &taggedNetblockBlocker{netblockBlocker: newNetblockBlocker(), rows: []firewall.BlockedEntry{{IP: ip, LoginSpray: true}}}
			if tc.cached {
				b.live[ip] = struct{}{}
			}
			rows, err := netblockTrackedRows(b, nil, firewall.LiveBlockedSnapshot{HasV6: tc.covered}, tc.listed)
			if err != nil || len(rows) != tc.want {
				t.Fatalf("rows=%v err=%v, want %d rows", rows, err, tc.want)
			}
		})
	}
}
