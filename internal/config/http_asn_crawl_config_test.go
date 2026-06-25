package config

import (
	"strings"
	"testing"
)

func TestHTTPASNCrawlConfigDefaults(t *testing.T) {
	// Unset keys take documented defaults.
	cfg, err := LoadBytes([]byte("thresholds: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	th := cfg.Thresholds
	if th.HTTPASNCrawlMinIPs != 25 || th.HTTPASNCrawlMinExpensive != 250 ||
		th.HTTPASNCrawlMinSharePct != 50 || th.HTTPASNCrawlWindowMin != 60 ||
		th.HTTPASNCrawlMaxTrackedIPs != 20000 || th.HTTPASNCrawl16PrefPct != 60 ||
		th.HTTPASNCrawlMaxPrefix != 8 {
		t.Fatalf("unexpected defaults: %+v", th)
	}
	if cfg.AutoResponse.HTTPASNCrawlTempban != "24h" {
		t.Fatalf("tempban default = %q want 24h", cfg.AutoResponse.HTTPASNCrawlTempban)
	}
	if len(th.HTTPASNCrawlReverseProxyASNs) != 3 {
		t.Fatalf("reverse-proxy seed = %v want [13335 54113 20940]", th.HTTPASNCrawlReverseProxyASNs)
	}
	if len(th.HTTPASNCrawlAllowlistASNs) != 0 {
		t.Fatalf("trust allowlist must ship empty, got %v", th.HTTPASNCrawlAllowlistASNs)
	}
}

func TestHTTPASNCrawlExplicitZeroDisables(t *testing.T) {
	cfg, err := LoadBytes([]byte("thresholds:\n  http_asn_crawl_min_ips: 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Thresholds.HTTPASNCrawlMinIPs != 0 {
		t.Fatalf("explicit 0 must be preserved, got %d", cfg.Thresholds.HTTPASNCrawlMinIPs)
	}
}

func TestHTTPASNCrawlReverseProxyExplicitEmpty(t *testing.T) {
	cfg, err := LoadBytes([]byte("thresholds:\n  http_asn_crawl_reverse_proxy_asns: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Thresholds.HTTPASNCrawlReverseProxyASNs) != 0 {
		t.Fatalf("explicit empty reverse-proxy list must be honored, got %v", cfg.Thresholds.HTTPASNCrawlReverseProxyASNs)
	}
}

func TestHTTPASNCrawlReverseProxySeedValues(t *testing.T) {
	cfg, err := LoadBytes([]byte("thresholds: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	seed := cfg.Thresholds.HTTPASNCrawlReverseProxyASNs
	if len(seed) != 3 {
		t.Fatalf("seed length = %d, want 3", len(seed))
	}
	if seed[0] != 13335 || seed[1] != 54113 || seed[2] != 20940 {
		t.Fatalf("seed = %v, want [13335 54113 20940]", seed)
	}
}

func TestHTTPASNCrawlHighAmpPctDefault(t *testing.T) {
	cfg, err := LoadBytes([]byte("thresholds: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Thresholds.HTTPASNCrawlHighAmpPct != 50 {
		t.Fatalf("high_amp_pct default = %d, want 50", cfg.Thresholds.HTTPASNCrawlHighAmpPct)
	}
	if cfg.Thresholds.HTTPASNCrawlHighVolumeMult != 4 {
		t.Fatalf("high_volume_mult default = %d, want 4", cfg.Thresholds.HTTPASNCrawlHighVolumeMult)
	}
}

func TestHTTPASNCrawlValidationRejectsNegativeInts(t *testing.T) {
	_, err := LoadBytes([]byte("thresholds:\n  http_asn_crawl_window_min: -1\n"))
	if err == nil {
		t.Fatal("expected error for negative http_asn_crawl_window_min")
	}
	if !strings.Contains(err.Error(), "http_asn_crawl") {
		t.Fatalf("error should mention http_asn_crawl, got: %v", err)
	}
}

func TestHTTPASNCrawlValidationRejectsInvalidTempban(t *testing.T) {
	_, err := LoadBytes([]byte("auto_response:\n  http_asn_crawl_tempban: \"notaduration\"\n"))
	if err == nil {
		t.Fatal("expected error for invalid http_asn_crawl_tempban duration")
	}
}

func TestHTTPASNCrawlValidationRejectsZeroTempban(t *testing.T) {
	_, err := LoadBytes([]byte("auto_response:\n  http_asn_crawl_tempban: \"0s\"\n"))
	if err == nil {
		t.Fatal("expected error for zero http_asn_crawl_tempban duration")
	}
}

func TestHTTPASNCrawlValidationRejectsInvalidASN(t *testing.T) {
	_, err := LoadBytes([]byte("thresholds:\n  http_asn_crawl_allowlist_asns: [0]\n"))
	if err == nil {
		t.Fatal("expected error for ASN=0 in allowlist")
	}
}

func TestHTTPASNCrawlValidationRejectsOutOfRangePercent(t *testing.T) {
	_, err := LoadBytes([]byte("thresholds:\n  http_asn_crawl_min_share_pct: 101\n"))
	if err == nil {
		t.Fatal("expected error for min_share_pct=101 (out of 1..100 range)")
	}
}

func TestHTTPASNCrawlValidationRejectsUnreachableIPThreshold(t *testing.T) {
	_, err := LoadBytes([]byte("thresholds:\n  http_asn_crawl_min_ips: 25\n  http_asn_crawl_max_tracked_ips: 10\n"))
	if err == nil {
		t.Fatal("expected error when max_tracked_ips is below min_ips")
	}
}
