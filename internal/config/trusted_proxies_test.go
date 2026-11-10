package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLoadRejectsNullTrustedProxyEntries(t *testing.T) {
	for _, key := range []string{"web_server", "challenge"} {
		for _, tc := range []struct {
			name, preamble, entries string
		}{
			{"null", "", "[192.0.2.10, null]"},
			{"tilde", "", "[192.0.2.10, ~]"},
			{"blank", "", "\n    - 192.0.2.10\n    -"},
			{"aliased entry", "hostname: &empty null\n", "[192.0.2.10, *empty]"},
			{"aliased list", "infra_ips: &proxies [192.0.2.10, null]\n", "*proxies"},
		} {
			t.Run(key+"/"+tc.name, func(t *testing.T) {
				data := []byte(fmt.Sprintf("%s%s:\n  trusted_proxies: %s\n", tc.preamble, key, tc.entries))
				cfg, err := LoadBytes(data)
				if err == nil || cfg != nil {
					t.Fatal("LoadBytes accepted an empty proxy entry and retained a partial trust list")
				}
				if !strings.Contains(err.Error(), key+".trusted_proxies") {
					t.Fatalf("error = %v, want the invalid proxy setting named", err)
				}
			})
		}
	}
}

func TestLoadRejectsInheritedNullTrustedProxyEntries(t *testing.T) {
	for _, key := range []string{"web_server", "challenge"} {
		t.Run(key, func(t *testing.T) {
			data := []byte(fmt.Sprintf("%s:\n  <<: {trusted_proxies: [192.0.2.10, null]}\n", key))
			_, err := LoadBytes(data)
			if err == nil || !strings.Contains(err.Error(), key+".trusted_proxies") {
				t.Fatalf("LoadBytes error = %v, want the inherited empty proxy entry refused", err)
			}
		})
	}
}

func TestLoadRejectsNullTrustedProxyEntriesFromDropIns(t *testing.T) {
	for _, key := range []string{"web_server", "challenge"} {
		t.Run(key, func(t *testing.T) {
			dir := t.TempDir()
			fragment := []byte(fmt.Sprintf("%s:\n  trusted_proxies: [null]\n", key))
			if err := os.WriteFile(filepath.Join(dir, "proxies.yaml"), fragment, 0o600); err != nil {
				t.Fatal(err)
			}
			main := []byte(fmt.Sprintf("%s:\n  trusted_proxies: [192.0.2.10]\n", key))
			_, err := LoadBytesWithDir(main, dir)
			if err == nil || !strings.Contains(err.Error(), key+".trusted_proxies") {
				t.Fatalf("LoadBytesWithDir error = %v, want the empty drop-in entry refused", err)
			}
		})
	}
}

func TestLoadAllowsEmptyTrustedProxyLists(t *testing.T) {
	for _, key := range []string{"web_server", "challenge"} {
		for _, value := range []string{"[]", "null", ""} {
			t.Run(key+"/"+value, func(t *testing.T) {
				cfg, err := LoadBytes([]byte(fmt.Sprintf("%s:\n  trusted_proxies: %s\n", key, value)))
				if err != nil || cfg == nil {
					t.Fatalf("LoadBytes did not return a config: %v", err)
				}
				if got := TrustedProxies(cfg).Len(); got != 0 {
					t.Fatalf("empty proxy list trusts %d entries", got)
				}
			})
		}
	}
}

func TestLoadPreservesTrustedProxyAliases(t *testing.T) {
	cfg, err := LoadBytes([]byte("web_server: &web\n  trusted_proxies: [&proxy 192.0.2.10, *proxy, 2001:db8::/32]\nchallenge:\n  <<: *web\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(cfg.WebServer.TrustedProxies) != 3 || len(cfg.Challenge.TrustedProxies) != 3 {
		t.Fatal("a proxy alias or inherited entry was dropped")
	}
	trusted := TrustedProxies(cfg)
	for _, addr := range []string{"192.0.2.10", "2001:db8::1"} {
		if !trusted.Covers(netip.MustParseAddr(addr)) {
			t.Fatalf("TrustedProxies does not cover %s", addr)
		}
	}
}

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

// An address of this host in web_server.trusted_proxies is never trusted, so
// requests a local proxy forwards count against nobody: validate says so as
// a warning, never an error that would stop a daemon that ran with it.
func TestValidateWarnsAboutAWebServerProxyOfThisHost(t *testing.T) {
	pinChallengeHost(t, "203.0.113.10")
	cfg := baseValidationConfig()
	cfg.WebServer.TrustedProxies = []string{"198.51.100.7", "127.0.0.1"}
	results := Validate(cfg)
	if hasResult(results, "error", "web_server.trusted_proxies") {
		t.Fatal("a local proxy entry must never be a validation error: it would stop the daemon")
	}
	i := slices.IndexFunc(results, func(r ValidationResult) bool {
		return r.Level == "warn" && r.Field == "web_server.trusted_proxies"
	})
	if i < 0 {
		t.Fatalf("want warn on web_server.trusted_proxies, got %v", results)
	}
	for _, want := range []string{"127.0.0.1", "address of this host", "count against nobody"} {
		if !strings.Contains(results[i].Message, want) {
			t.Errorf("message %q lacks %q", results[i].Message, want)
		}
	}
	cfg.WebServer.TrustedProxies = []string{"198.51.100.7", "192.0.2.0/24"}
	if hasResult(Validate(cfg), "warn", "web_server.trusted_proxies") {
		t.Fatal("remote proxy entries must not warn")
	}
}
