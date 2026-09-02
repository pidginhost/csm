package firewall

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			cidrs, err := fetchCIDRList(&http.Client{Timeout: 5 * time.Second}, srv.URL)
			if err == nil {
				t.Fatalf("body without CIDRs accepted as list %v", cidrs)
			}
		})
	}
}

// A line longer than the scanner buffer stops the scan with an error that
// the fetch must surface instead of returning the partial list as complete.
func TestFetchCIDRListSurfacesScannerErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("173.245.48.0/20\n" + strings.Repeat("x", 70000) + "\n"))
	}))
	defer srv.Close()
	if _, err := fetchCIDRList(&http.Client{Timeout: 5 * time.Second}, srv.URL); err == nil {
		t.Fatal("oversized line accepted; partial list returned as complete")
	}
}

func TestFetchCIDRListAcceptsRealList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("173.245.48.0/20\n103.21.244.0/22\n# trailing comment\n"))
	}))
	defer srv.Close()
	cidrs, err := fetchCIDRList(&http.Client{Timeout: 5 * time.Second}, srv.URL)
	if err != nil || len(cidrs) != 2 {
		t.Fatalf("cidrs = %v, err = %v; want the two ranges", cidrs, err)
	}
}
