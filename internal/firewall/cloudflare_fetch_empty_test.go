package firewall

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// A 200 response that carries no CIDR (a captive portal, a proxy error page,
// an upstream HTML interstitial) is not an empty Cloudflare list: publishing
// it would flush every Cloudflare guard and turn the next brute-force finding
// carrying an edge address into a block of that edge for every visitor.
func TestFetchCIDRListRejectsBodiesWithoutCIDRs(t *testing.T) {
	for name, body := range map[string]string{
		"html interstitial": "<html><body>Attention Required! | Cloudflare</body></html>\n",
		"empty body":        "",
		"comments only":     "# temporarily unavailable\n",
	} {
		t.Run(name, func(t *testing.T) {
			client := geoIPTestClient(http.StatusOK, io.NopCloser(strings.NewReader(body)))
			cidrs, err := fetchCIDRList(context.Background(), client, "https://example.test/ips")
			if err == nil {
				t.Fatalf("body without CIDRs accepted as list %v", cidrs)
			}
		})
	}
}

// A line longer than the scanner buffer stops the scan with an error that
// the fetch must surface instead of returning the partial list as complete.
func TestFetchCIDRListSurfacesScannerErrors(t *testing.T) {
	body := "173.245.48.0/20\n" + strings.Repeat("x", 70000) + "\n"
	client := geoIPTestClient(http.StatusOK, io.NopCloser(strings.NewReader(body)))
	if _, err := fetchCIDRList(context.Background(), client, "https://example.test/ips"); err == nil {
		t.Fatal("oversized line accepted; partial list returned as complete")
	}
}

func TestFetchCIDRListAcceptsRealList(t *testing.T) {
	body := "173.245.48.0/20\n103.21.244.0/22\n# trailing comment\n"
	client := geoIPTestClient(http.StatusOK, io.NopCloser(strings.NewReader(body)))
	cidrs, err := fetchCIDRList(context.Background(), client, "https://example.test/ips")
	if err != nil || len(cidrs) != 2 {
		t.Fatalf("cidrs = %v, err = %v; want the two ranges", cidrs, err)
	}
}

func TestFetchCloudflareIPsReturnsFreshFamilyWhenOtherFails(t *testing.T) {
	client := geoIPTestClientForURLs(map[string]geoIPTestResponse{
		cfIPv4URL: {status: http.StatusServiceUnavailable, body: "unavailable"},
		cfIPv6URL: {status: http.StatusOK, body: "2400:cb00::/32\n"},
	})
	ipv4, ipv6, err := fetchCloudflareIPs(context.Background(), client)
	if err == nil {
		t.Fatal("one-family failure was not reported")
	}
	if len(ipv4) != 0 || len(ipv6) != 1 || ipv6[0] != "2400:cb00::/32" {
		t.Fatalf("ranges = %v, %v; want fresh IPv6 retained", ipv4, ipv6)
	}
}
