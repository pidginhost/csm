package daemon

import (
	"net/netip"
	"strconv"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestReputationWhitelistAddressForms(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry string
		addr  string
		want  bool
	}{
		{"ipv4", "203.0.113.50", "203.0.113.50", true},
		{"ipv4 mapped", "203.0.113.50", "::ffff:203.0.113.50", true},
		{"mapped entry", "::ffff:203.0.113.50", "203.0.113.50", true},
		{"expanded ipv6", "2001:DB8::70", "2001:db8:0:0:0:0:0:70", true},
		{"trimmed entry", " 2001:DB8::70 ", "2001:db8::70", true},
		{"different ipv6", "2001:DB8::70", "2001:db8::71", false},
		{"scoped literal", "2001:db8::70%eth0", "2001:db8::70%eth0", true},
		{"scope is not discarded", "2001:db8::70%eth0", "2001:db8::70", false},
		{"different scope", "2001:db8::70%eth0", "2001:db8::70%eth1", false},
		{"unscoped entry", "2001:db8::70", "2001:db8::70%eth0", false},
		{"exact subnet", "203.0.113.0/24", "203.0.113.0/24", true},
		{"subnet is not a host allowlist", "203.0.113.0/24", "203.0.113.50", false},
		{"empty entry", "", "", false},
		{"blank entry", " ", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Reputation.Whitelist = []string{tc.entry}
			var whitelist reputationWhitelist
			if got := whitelist.contains(cfg, tc.addr); got != tc.want {
				t.Fatalf("whitelisted = %v, want %v", got, tc.want)
			}
		})
	}
	var whitelist reputationWhitelist
	if whitelist.contains(nil, "203.0.113.50") {
		t.Fatal("nil config whitelisted an address")
	}
}

func TestReputationWhitelistFollowsSnapshots(t *testing.T) {
	old := &config.Config{}
	old.Reputation.Whitelist = []string{"203.0.113.50", "2001:DB8::70"}
	next := &config.Config{}
	next.Reputation.Whitelist = []string{"203.0.113.60", "2001:db8::70"}
	var whitelist reputationWhitelist
	for _, cfg := range []*config.Config{old, next, {}, nil, old, next} {
		wantOld, wantNext := cfg == old, cfg == next
		for _, tc := range []struct {
			addr string
			want bool
		}{
			{"203.0.113.50", wantOld},
			{"203.0.113.60", wantNext},
			{"2001:db8::70", wantOld || wantNext},
			{"203.0.113.99", false},
		} {
			if got := whitelist.contains(cfg, tc.addr); got != tc.want {
				t.Errorf("contains(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		}
	}
}

// A reader that captured the previous config may finish after a reload.
// Every lookup must use its own snapshot, even while other readers rebuild.
func TestReputationWhitelistConcurrentSnapshots(t *testing.T) {
	configs := []*config.Config{{}, {}}
	configs[0].Reputation.Whitelist = []string{"203.0.113.50"}
	configs[1].Reputation.Whitelist = []string{"203.0.113.60"}
	var whitelist reputationWhitelist
	var readers sync.WaitGroup
	for i := range 8 {
		readers.Go(func() {
			cfg := configs[i%len(configs)]
			for range 1000 {
				if !whitelist.contains(cfg, cfg.Reputation.Whitelist[0]) {
					t.Error("lookup lost the address in its config snapshot")
					return
				}
				if whitelist.contains(cfg, configs[(i+1)%len(configs)].Reputation.Whitelist[0]) {
					t.Error("lookup used an address from another config snapshot")
					return
				}
			}
		})
	}
	readers.Wait()
}

func BenchmarkReputationWhitelistLookup(b *testing.B) {
	for _, size := range []int{0, 32, 1024, 16384} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			cfg := &config.Config{}
			addr := netip.MustParseAddr("2001:db8::1")
			for range size {
				cfg.Reputation.Whitelist = append(cfg.Reputation.Whitelist, addr.String())
				addr = addr.Next()
			}
			var whitelist reputationWhitelist
			_ = whitelist.contains(cfg, "203.0.113.50")
			b.ReportAllocs()
			for b.Loop() {
				if whitelist.contains(cfg, "203.0.113.50") {
					b.Fatal("unlisted address matched")
				}
			}
		})
	}
}
