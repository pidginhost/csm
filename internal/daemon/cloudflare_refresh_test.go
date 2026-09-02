package daemon

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

func TestRefreshCloudflareIPsMergesFreshAndCachedFamilies(t *testing.T) {
	orig := fetchCloudflareIPs
	t.Cleanup(func() { fetchCloudflareIPs = orig })
	t.Cleanup(func() { checks.SetCloudflareNets(nil) })

	for name, tc := range map[string]struct {
		fetch func() ([]string, []string, error)
		want4 []string
		want6 []string
	}{
		"fresh IPv4": {
			fetch: func() ([]string, []string, error) {
				return []string{"198.51.100.0/24"}, nil, errors.New("IPv6 unavailable")
			},
			want4: []string{"198.51.100.0/24"},
			want6: []string{"2400:cb00::/32"},
		},
		"fresh IPv6": {
			fetch: func() ([]string, []string, error) {
				return nil, []string{"2001:db8:100::/48"}, errors.New("IPv4 unavailable")
			},
			want4: []string{"173.245.48.0/20"},
			want6: []string{"2001:db8:100::/48"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			if err := firewall.SaveCFState(state, []string{"173.245.48.0/20"}, []string{"2400:cb00::/32"}, time.Now().Add(-time.Hour)); err != nil {
				t.Fatal(err)
			}
			fetchCloudflareIPs = tc.fetch
			d := &Daemon{cfg: &config.Config{StatePath: state}}
			d.refreshCloudflareIPs()
			got4, got6 := firewall.LoadCFState(state)
			if len(got4) != 1 || got4[0] != tc.want4[0] || len(got6) != 1 || got6[0] != tc.want6[0] {
				t.Fatalf("saved ranges = %v, %v; want %v, %v", got4, got6, tc.want4, tc.want6)
			}
			for _, ip := range []string{firstAddress(tc.want4[0]), firstAddress(tc.want6[0])} {
				if !checks.IsCloudflareIP(net.ParseIP(ip)) {
					t.Fatalf("checks package did not receive merged Cloudflare range for %s", ip)
				}
			}
		})
	}
}

func TestRefreshCloudflareIPsRestoresCachedRangesAfterFetchFailure(t *testing.T) {
	orig := fetchCloudflareIPs
	t.Cleanup(func() { fetchCloudflareIPs = orig })
	t.Cleanup(func() { checks.SetCloudflareNets(nil) })

	state := t.TempDir()
	refreshed := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := firewall.SaveCFState(state, []string{"173.245.48.0/20"}, []string{"2400:cb00::/32"}, refreshed); err != nil {
		t.Fatal(err)
	}
	fetchCloudflareIPs = func() ([]string, []string, error) {
		return nil, nil, os.ErrDeadlineExceeded
	}
	d := &Daemon{cfg: &config.Config{StatePath: state}}
	d.refreshCloudflareIPs()

	if got := firewall.LoadCFRefreshTime(state); !got.Equal(refreshed) {
		t.Fatalf("failed fetch rewrote refresh time to %s; want %s", got, refreshed)
	}
	for _, ip := range []string{"173.245.48.1", "2400:cb00::1"} {
		if !checks.IsCloudflareIP(net.ParseIP(ip)) {
			t.Fatalf("cached Cloudflare range was not restored for %s", ip)
		}
	}
}

func TestRefreshCloudflareIPsUsesPartialFirstFetch(t *testing.T) {
	orig := fetchCloudflareIPs
	t.Cleanup(func() { fetchCloudflareIPs = orig })
	t.Cleanup(func() { checks.SetCloudflareNets(nil) })

	state := t.TempDir()
	fetchCloudflareIPs = func() ([]string, []string, error) {
		return []string{"198.51.100.0/24"}, nil, errors.New("IPv6 unavailable")
	}
	d := &Daemon{cfg: &config.Config{StatePath: state}}
	d.refreshCloudflareIPs()

	got4, got6 := firewall.LoadCFState(state)
	if len(got4) != 1 || got4[0] != "198.51.100.0/24" || len(got6) != 0 {
		t.Fatalf("first partial refresh = %v, %v; want fresh IPv4 retained", got4, got6)
	}
	if !checks.IsCloudflareIP(net.ParseIP("198.51.100.1")) {
		t.Fatal("first partial refresh did not install the available family")
	}
}

func firstAddress(cidr string) string {
	return strings.SplitN(cidr, "/", 2)[0]
}
