//go:build linux && nftkernel

package firewall

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

func isolatedFirewallNamespace(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		_ = unix.Close(fd)
		runtime.UnlockOSThread()
		t.Fatalf("kernel firewall tests require CAP_SYS_ADMIN and CAP_NET_ADMIN: %v", err)
	}
	t.Cleanup(func() {
		err := unix.Setns(fd, unix.CLONE_NEWNET)
		_ = unix.Close(fd)
		if err != nil {
			t.Fatalf("restore network namespace: %v", err)
		}
		runtime.UnlockOSThread()
	})
}

func assertKernelIntervalSet(t *testing.T, e *Engine, set *nftables.Set, want map[string]bool) {
	t.Helper()
	elements, err := e.conn.GetSetElements(set)
	if err != nil {
		t.Fatal(err)
	}
	if len(elements) != len(want) {
		t.Fatalf("%s has %d boundaries, want %d: %+v", set.Name, len(elements), len(want), elements)
	}
	for _, elem := range elements {
		key := net.IP(elem.Key).String()
		end, ok := want[key]
		if !ok || end != elem.IntervalEnd {
			t.Fatalf("%s unexpected boundary %s (end=%v), want %v", set.Name, key, elem.IntervalEnd, want)
		}
	}
}

func TestKernelInfraIntervalsApplyAndReload(t *testing.T) {
	for _, tc := range []struct {
		name         string
		infra        []string
		want4, want6 map[string]bool
	}{
		{"mapped boundary", []string{"::ffff:198.51.100.7/120", "::/80"}, map[string]bool{"198.51.100.0": false, "198.51.101.0": true}, map[string]bool{"::": false, "::1:0:0:0": true}},
		{"nested and duplicate", []string{"198.51.100.0/24", "198.51.100.128/25", "198.51.100.2", "198.51.100.0/24", "2001:db8::/64", "2001:db8::1", "2001:db8::/80"}, map[string]bool{"198.51.100.0": false, "198.51.101.0": true}, map[string]bool{"2001:db8::": false, "2001:db8:0:1::": true}},
		{"adjacent", []string{"198.51.100.0/25", "198.51.100.128/25", "2001:db8::/65", "2001:db8:0:0:8000::/65"}, map[string]bool{"198.51.100.0": false, "198.51.101.0": true}, map[string]bool{"2001:db8::": false, "2001:db8:0:1::": true}},
		{"full address space", []string{"0.0.0.0/0", "198.51.100.1", "::/0", "2001:db8::1"}, map[string]bool{"0.0.0.0": false}, map[string]bool{"::": false}},
		{"upper bounds", []string{"255.255.255.254/31", "255.255.255.255", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}, map[string]bool{"255.255.255.254": false}, map[string]bool{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe": false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatedFirewallNamespace(t)
			cfg := &FirewallConfig{Enabled: true, IPv6: true, InfraIPs: tc.infra}
			e, err := NewEngine(cfg, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := e.Apply(); err != nil {
					t.Fatalf("apply: %v", err)
				}
				assertKernelIntervalSet(t, e, e.setInfra, tc.want4)
				assertKernelIntervalSet(t, e, e.setInfra6, tc.want6)
			}
			cfg.InfraIPs = []string{"198.51.100.128/25", "2001:db8::/80"}
			if err := e.Apply(); err != nil {
				t.Fatalf("reload after removing covering entries: %v", err)
			}
			assertKernelIntervalSet(t, e, e.setInfra, map[string]bool{"198.51.100.128": false, "198.51.101.0": true})
			assertKernelIntervalSet(t, e, e.setInfra6, map[string]bool{"2001:db8::": false, "2001:db8:0:0:1::": true})
		})
	}
}

func TestKernelOverlappingSubnetRemovalAndExpiry(t *testing.T) {
	isolatedFirewallNamespace(t)
	e, err := NewEngine(&FirewallConfig{Enabled: true, IPv6: true}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	for _, cidr := range []string{"198.51.100.0/24", "198.51.100.128/25", "2001:db8::/64", "2001:db8::/80"} {
		if err := e.BlockSubnet(cidr, "via CLI", time.Hour); err != nil {
			t.Fatalf("block %s: %v", cidr, err)
		}
	}
	original := make(map[string]SubnetEntry)
	for _, entry := range e.BlockedSubnets() {
		original[entry.CIDR] = entry
	}
	assertKernelIntervalSet(t, e, e.setBlockedNet, map[string]bool{"198.51.100.0": false, "198.51.101.0": true})
	assertKernelIntervalSet(t, e, e.setBlockedNet6, map[string]bool{"2001:db8::": false, "2001:db8:0:1::": true})
	e.setBlockedNet6.Name = "missing_subnet_set"
	if err := e.UnblockSubnet("198.51.100.0/24"); err == nil {
		t.Fatal("incomplete kernel transaction reported success")
	}
	e.setBlockedNet6.Name = "blocked_nets6"
	assertKernelIntervalSet(t, e, e.setBlockedNet, map[string]bool{"198.51.100.0": false, "198.51.101.0": true})
	if got := e.BlockedSubnets(); len(got) != 4 {
		t.Fatalf("failed removal changed state: %+v", got)
	}
	e.SetConfig(&FirewallConfig{Enabled: true, IPv6: false})
	if err := e.UnblockSubnet("198.51.100.0/24"); err != nil {
		t.Fatal(err)
	}
	assertKernelIntervalSet(t, e, e.setBlockedNet6, map[string]bool{"2001:db8::": false, "2001:db8:0:1::": true})
	e.SetConfig(&FirewallConfig{Enabled: true, IPv6: true})
	assertKernelIntervalSet(t, e, e.setBlockedNet, map[string]bool{"198.51.100.128": false, "198.51.101.0": true})
	state := e.loadStateFile()
	for i := range state.BlockedNet {
		if state.BlockedNet[i].CIDR == "2001:db8::/64" {
			state.BlockedNet[i].Source = SourceAutoResponse
			state.BlockedNet[i].ExpiresAt = time.Now().Add(-time.Second)
		}
	}
	if err := e.saveState(&state); err != nil {
		t.Fatal(err)
	}
	if got := e.CleanExpiredSubnets(); got != 1 {
		t.Fatalf("expired %d entries, want 1", got)
	}
	assertKernelIntervalSet(t, e, e.setBlockedNet6, map[string]bool{"2001:db8::": false, "2001:db8:0:0:1::": true})
	survivors := e.BlockedSubnets()
	if len(survivors) != 2 {
		t.Fatalf("surviving entries = %+v, want two", survivors)
	}
	for _, got := range survivors {
		want := original[got.CIDR]
		if got.Source != SourceCLI || got.Reason != want.Reason || !got.BlockedAt.Equal(want.BlockedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
			t.Fatalf("surviving entry changed: got %+v, want %+v", got, want)
		}
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	assertKernelIntervalSet(t, e, e.setBlockedNet6, map[string]bool{"2001:db8::": false, "2001:db8:0:0:1::": true})
}

func TestKernelIntervalFeedRefreshes(t *testing.T) {
	isolatedFirewallNamespace(t)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"AA.cidr":  "198.51.100.0/24\n198.51.100.128/25\n",
		"BB.cidr":  "198.51.100.0/24\n",
		"AA.cidr6": "2001:db8::/64\n",
		"BB.cidr6": "2001:db8::/80\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &FirewallConfig{Enabled: true, IPv6: true, CountryDBPath: dir, CountryBlock: []string{"AA", "BB"}, DOSExemptRanges: []string{"198.51.100.128/25", "2001:db8::/80"}}
	e, err := NewEngine(cfg, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e.SetDOSExemptProviderNets([]*net.IPNet{mustCIDR(t, "198.51.100.0/24"), mustCIDR(t, "2001:db8::/64")})
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	want4 := map[string]bool{"198.51.100.0": false, "198.51.101.0": true}
	want6 := map[string]bool{"2001:db8::": false, "2001:db8:0:1::": true}
	assertKernelIntervalSet(t, e, e.setCountry, want4)
	assertKernelIntervalSet(t, e, e.setCountry6, want6)
	assertKernelIntervalSet(t, e, e.setDOSExempt, want4)
	assertKernelIntervalSet(t, e, e.setDOSExempt6, want6)
	if err := e.RefreshDOSExemptSets(nil); err != nil {
		t.Fatal(err)
	}
	assertKernelIntervalSet(t, e, e.setDOSExempt, map[string]bool{"198.51.100.128": false, "198.51.101.0": true})
	assertKernelIntervalSet(t, e, e.setDOSExempt6, map[string]bool{"2001:db8::": false, "2001:db8:0:0:1::": true})
	for range 2 {
		if err := e.UpdateCloudflareSet([]string{"198.51.100.0/24", "198.51.100.128/25"}, []string{"2001:db8::/64", "2001:db8::/80"}); err != nil {
			t.Fatal(err)
		}
		assertKernelIntervalSet(t, e, e.setCFWhitelist, want4)
		assertKernelIntervalSet(t, e, e.setCFWhitelist6, want6)
	}
	if err := e.UpdateCloudflareSet([]string{"255.255.255.255/32"}, []string{"::/0"}); err != nil {
		t.Fatal(err)
	}
	assertKernelIntervalSet(t, e, e.setCFWhitelist, map[string]bool{"255.255.255.255": false})
	assertKernelIntervalSet(t, e, e.setCFWhitelist6, map[string]bool{"::": false})
}

func TestKernelPartiallyOverlappingIntervals(t *testing.T) {
	isolatedFirewallNamespace(t)
	for _, family := range []struct {
		typ                   nftables.SetDatatype
		first, mid, end, last string
	}{
		{nftables.TypeIPAddr, "198.51.100.1", "198.51.100.5", "198.51.100.8", "198.51.100.12"},
		{nftables.TypeIP6Addr, "2001:db8::1", "2001:db8::5", "2001:db8::8", "2001:db8::c"},
	} {
		conn := &nftables.Conn{}
		table := conn.AddTable(&nftables.Table{Name: "partial", Family: nftables.TableFamilyINet})
		set := &nftables.Set{Table: table, Name: "ranges", KeyType: family.typ, Interval: true}
		raw := intervalSetElements(canonicalIPBytes(net.ParseIP(family.mid)), canonicalIPBytes(net.ParseIP(family.last)))
		raw = appendIntervalSetElements(raw, canonicalIPBytes(net.ParseIP(family.first)), canonicalIPBytes(net.ParseIP(family.end)))
		if err := conn.AddSet(set, normalizeIntervalElements(raw)); err != nil {
			t.Fatal(err)
		}
		if err := conn.Flush(); err != nil {
			t.Fatal(err)
		}
		end := nextIP(net.ParseIP(family.last)).String()
		assertKernelIntervalSet(t, &Engine{conn: conn}, set, map[string]bool{family.first: false, end: true})
		conn.DelTable(table)
		if err := conn.Flush(); err != nil {
			t.Fatal(err)
		}
	}
}
