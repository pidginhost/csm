package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsInvalidTrustedProxies(t *testing.T) {
	cases := []struct {
		yaml string
		want []string
	}{
		{"web_server:\n  trusted_proxies: [\"192.0.2.0/24\", \"proxy.example\"]\n", []string{"web_server.trusted_proxies[1]", "proxy.example"}},
		{"challenge:\n  trusted_proxies: [\"0.0.0.0/0\"]\n", []string{"challenge.trusted_proxies[0]", "default route"}},
		{"web_server:\n  trusted_proxies: [\"\"]\n", []string{"web_server.trusted_proxies[0]", "empty"}},
	}
	for _, tc := range cases {
		_, err := LoadBytes([]byte(tc.yaml))
		if err == nil {
			t.Fatalf("LoadBytes(%q) = nil error; an unreadable trusted proxy entry must not be dropped silently", tc.yaml)
		}
		for _, want := range tc.want {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("LoadBytes(%q) error %q lacks %q", tc.yaml, err, want)
			}
		}
	}
}

func TestTrustedProxiesUnionsBothKeys(t *testing.T) {
	cfg, err := LoadBytes([]byte("web_server:\n  trusted_proxies: [\"192.0.2.10\"]\nchallenge:\n  trusted_proxies: [\"198.51.100.0/24\"]\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	trusted := TrustedProxies(cfg)
	for _, addr := range []string{"192.0.2.10", "198.51.100.9"} {
		if !trusted.Has(netip.MustParseAddr(addr)) {
			t.Fatalf("TrustedProxies().Has(%s) = false; both keys name trusted proxies", addr)
		}
	}
	if trusted.Has(netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("TrustedProxies().Has(203.0.113.9) = true")
	}
	if TrustedProxies(nil).Len() != 0 || TrustedProxies(&Config{}).Len() != 0 {
		t.Fatal("an empty config trusts no proxy")
	}
}

// A drop-in's entry is checked after the merge, like the main file's.
func TestLoadRejectsAnInvalidTrustedProxyFromADropIn(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "proxies.yaml"), []byte("challenge:\n  trusted_proxies: [\"192.0.2.0/33\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadBytesWithDir([]byte("web_server:\n  trusted_proxies: [\"192.0.2.10\"]\n"), dir)
	if err == nil || !strings.Contains(err.Error(), "challenge.trusted_proxies") {
		t.Fatalf("LoadBytesWithDir error = %v, want the drop-in's key named", err)
	}
}

// A config built without loading that holds an unreadable entry trusts no
// proxy, never the readable part of its list.
func TestTrustedProxiesRefusesAnUnloadedInvalidList(t *testing.T) {
	for _, key := range []string{"web_server", "challenge"} {
		cfg := &Config{}
		entries := []string{"192.0.2.10", "proxy.example"}
		if key == "web_server" {
			cfg.WebServer.TrustedProxies = entries
		} else {
			cfg.Challenge.TrustedProxies = entries
		}
		if got := TrustedProxies(cfg); got.Len() != 0 || got.Covers(netip.MustParseAddr("192.0.2.10")) {
			t.Fatalf("%s: TrustedProxies kept %d entries from an unreadable list", key, got.Len())
		}
	}
}
