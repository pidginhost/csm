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

// An upgrade must keep a daemon that ran with an empty entry: Load skips it,
// the readable entries keep working, and validate warns.
func TestLoadSkipsNullTrustedProxyEntries(t *testing.T) {
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
				if err != nil || cfg == nil {
					t.Fatalf("LoadBytes refused an empty proxy entry: %v", err)
				}
				if got := TrustedProxies(cfg); got.Len() != 1 || !got.Covers(netip.MustParseAddr("192.0.2.10")) {
					t.Fatalf("TrustedProxies kept %d entries, want only 192.0.2.10", got.Len())
				}
				assertTrustedProxyWarning(t, cfg, key, "is empty")
			})
		}
	}
}

func TestLoadSkipsInheritedNullTrustedProxyEntries(t *testing.T) {
	for _, key := range []string{"web_server", "challenge"} {
		t.Run(key, func(t *testing.T) {
			data := []byte(fmt.Sprintf("%s:\n  <<: {trusted_proxies: [192.0.2.10, null]}\n", key))
			cfg, err := LoadBytes(data)
			if err != nil {
				t.Fatalf("LoadBytes refused an inherited empty proxy entry: %v", err)
			}
			assertTrustedProxyWarning(t, cfg, key, "is empty")
		})
	}
}

func TestLoadSkipsNullTrustedProxyEntriesFromDropIns(t *testing.T) {
	for _, key := range []string{"web_server", "challenge"} {
		t.Run(key, func(t *testing.T) {
			dir := t.TempDir()
			fragment := []byte(fmt.Sprintf("%s:\n  trusted_proxies: [null]\n", key))
			if err := os.WriteFile(filepath.Join(dir, "proxies.yaml"), fragment, 0o600); err != nil {
				t.Fatal(err)
			}
			main := []byte(fmt.Sprintf("%s:\n  trusted_proxies: [192.0.2.10]\n", key))
			cfg, err := LoadBytesWithDir(main, dir)
			if err != nil {
				t.Fatalf("LoadBytesWithDir refused an empty drop-in entry: %v", err)
			}
			assertTrustedProxyWarning(t, cfg, key, "is empty")
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

// yaml.v3 accepted scalar entries as strings before proxy validation was
// introduced. Main config and drop-ins must retain that loading behavior.
func TestLoadKeepsLegacyScalarTrustedProxyEntries(t *testing.T) {
	for _, key := range []string{"web_server", "challenge"} {
		for _, dropIn := range []bool{false, true} {
			for _, value := range []string{"false", "123", "1.5", "2026-01-01", "null", `""`, `"invalid"`} {
				t.Run(fmt.Sprintf("%s/dropIn=%t/%s", key, dropIn, value), func(t *testing.T) {
					main := []byte(fmt.Sprintf("%s:\n  trusted_proxies: [192.0.2.10]\n", key))
					body := []byte(fmt.Sprintf("%s:\n  trusted_proxies: [192.0.2.10, %s]\n", key, value))
					var cfg *Config
					var err error
					if dropIn {
						dir := t.TempDir()
						fragment := []byte(fmt.Sprintf("%s:\n  trusted_proxies: [%s]\n", key, value))
						if writeErr := os.WriteFile(filepath.Join(dir, "proxies.yaml"), fragment, 0o600); writeErr != nil {
							t.Fatal(writeErr)
						}
						cfg, err = LoadBytesWithDir(main, dir)
					} else {
						cfg, err = LoadBytes(body)
					}
					if err != nil {
						t.Fatalf("legacy scalar prevented loading: %v", err)
					}
					if trusted := TrustedProxies(cfg); trusted.Len() != 1 || !trusted.Covers(netip.MustParseAddr("192.0.2.10")) {
						t.Fatalf("usable proxy was lost: %+v", trusted)
					}
					assertTrustedProxyWarning(t, cfg, key, "skips")
					if key == "challenge" && !hasResult(ValidateDeepSection(cfg, key), "error", "challenge.trusted_proxies") {
						t.Fatal("Settings save accepted an unusable proxy")
					}
				})
			}
		}
	}
}

// Validate reports an unusable entry as a warning, never an error: an error
// aborts daemon start and reload, and 4.10.2 ran with such entries.
func TestValidateWarnsAboutUnusableTrustedProxies(t *testing.T) {
	cases := []struct {
		yaml, key string
		want      []string
	}{
		{"web_server:\n  trusted_proxies: [\"192.0.2.0/24\", \"proxy.example\"]\n", "web_server", []string{"web_server.trusted_proxies[1]", "proxy.example", "skips"}},
		{"challenge:\n  trusted_proxies: [\"0.0.0.0/0\"]\n", "challenge", []string{"challenge.trusted_proxies[0]", "default route", "count against nobody"}},
		{"web_server:\n  trusted_proxies: [\"\"]\n", "web_server", []string{"web_server.trusted_proxies[0]", "empty"}},
	}
	for _, tc := range cases {
		cfg, err := LoadBytes([]byte(tc.yaml))
		if err != nil {
			t.Fatalf("LoadBytes(%q): %v; an unusable entry must not stop the daemon", tc.yaml, err)
		}
		for _, want := range tc.want {
			assertTrustedProxyWarning(t, cfg, tc.key, want)
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
func TestLoadSkipsAnInvalidTrustedProxyFromADropIn(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "proxies.yaml"), []byte("challenge:\n  trusted_proxies: [\"192.0.2.0/33\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadBytesWithDir([]byte("web_server:\n  trusted_proxies: [\"192.0.2.10\"]\n"), dir)
	if err != nil {
		t.Fatalf("LoadBytesWithDir: %v", err)
	}
	if !TrustedProxies(cfg).Covers(netip.MustParseAddr("192.0.2.10")) {
		t.Fatal("the readable web_server entry was dropped")
	}
	assertTrustedProxyWarning(t, cfg, "challenge", "192.0.2.0/33")
}

// An unusable entry is skipped on its own, as 4.10.2 skipped it, so a typo
// never drops the proxies listed beside it.
func TestTrustedProxiesSkipsOnlyUnusableEntries(t *testing.T) {
	for _, key := range []string{"web_server", "challenge"} {
		cfg := &Config{}
		entries := []string{"192.0.2.10", "proxy.example"}
		if key == "web_server" {
			cfg.WebServer.TrustedProxies = entries
		} else {
			cfg.Challenge.TrustedProxies = entries
		}
		if got := TrustedProxies(cfg); got.Len() != 1 || !got.Covers(netip.MustParseAddr("192.0.2.10")) {
			t.Fatalf("%s: TrustedProxies kept %d entries, want the readable one", key, got.Len())
		}
	}
}

func assertTrustedProxyWarning(t *testing.T, cfg *Config, key, want string) {
	t.Helper()
	field := key + ".trusted_proxies"
	results := Validate(cfg)
	if hasResult(results, "error", field) {
		t.Fatalf("%s is a validation error; it would stop the daemon", field)
	}
	for _, r := range results {
		if r.Level == "warn" && r.Field == field && strings.Contains(r.Message, want) {
			return
		}
	}
	t.Fatalf("want a %s warning containing %q, got %v", field, want, results)
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

// Settings save is where an operator types a new entry: there an unusable
// challenge.trusted_proxies entry is an error, never only a warning.
func TestValidateDeepSectionRefusesUnusableChallengeProxies(t *testing.T) {
	cfg := baseValidationConfig()
	cfg.Challenge.TrustedProxies = []string{"192.0.2.10", "0.0.0.0/0"}
	if !hasResult(ValidateDeepSection(cfg, "challenge"), "error", "challenge.trusted_proxies") {
		t.Fatal("Settings save must refuse a challenge.trusted_proxies catch-all")
	}
	cfg.Challenge.TrustedProxies = []string{"192.0.2.10"}
	if hasResult(ValidateDeepSection(cfg, "challenge"), "error", "challenge.trusted_proxies") {
		t.Fatal("a readable entry must save")
	}
}

// A skipped catch-all trusts nothing, so it is reported once, as unusable,
// rather than as a host-local proxy.
func TestLocalTrustChecksIgnoreSkippedCatchAlls(t *testing.T) {
	pinChallengeHost(t, "203.0.113.10")
	for _, entry := range []string{"0.0.0.0/0", "::/0", "::ffff:0:0/96"} {
		if err := ChallengeLocalTrustError([]string{entry}); err != nil {
			t.Errorf("ChallengeLocalTrustError(%q) = %v, want nil", entry, err)
		}
		if err := WebServerLocalTrustError([]string{entry}); err != nil {
			t.Errorf("WebServerLocalTrustError(%q) = %v, want nil", entry, err)
		}
	}
	if ChallengeLocalTrustError([]string{"0.0.0.0/0", "127.0.0.1"}) == nil {
		t.Error("a usable entry of this host beside a catch-all must still be reported")
	}
}
