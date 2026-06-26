package mailranges

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestLoadCache_UsesLastGoodBeforeEmbedded seeds an on-disk cache with two
// RFC 5737 provider ranges, loads it, and asserts ProviderNets returns exactly
// those ranges - not the embedded snapshot content.
func TestLoadCache_UsesLastGoodBeforeEmbedded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mailranges.json")

	seed := cacheFile{
		RefreshedAt: 1700000001,
		Providers: map[string][]string{
			"testprovider": {"192.0.2.0/24", "198.51.100.0/24"},
		},
	}
	data, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	if err := LoadCache(path); err != nil {
		t.Fatalf("LoadCache: %v", err)
	}

	nets := ProviderNets()
	if len(nets) != 2 {
		t.Fatalf("want 2 nets from cache, got %d", len(nets))
	}

	want := map[string]bool{
		"192.0.2.0/24":    true,
		"198.51.100.0/24": true,
	}
	for _, n := range nets {
		s := n.String()
		if !want[s] {
			t.Errorf("unexpected net in result: %s", s)
		}
		delete(want, s)
	}
	for s := range want {
		t.Errorf("missing net from cache: %s", s)
	}
}

// TestLoadCache_FallsBackToEmbedded calls LoadCache with a nonexistent path
// and asserts that the embedded snapshot is used, yielding a non-empty result.
func TestLoadCache_FallsBackToEmbedded(t *testing.T) {
	if err := LoadCache("/nonexistent/mailranges.json"); err != nil {
		t.Fatalf("LoadCache with nonexistent path: %v", err)
	}

	nets := ProviderNets()
	if len(nets) == 0 {
		t.Fatal("expected non-empty ProviderNets() from embedded snapshot fallback")
	}
}

// TestProviderNetsReturnsCopy verifies that mutating the slice or net.IP bytes
// returned by ProviderNets does not affect the atomic store. A subsequent call
// must still return the original CIDR strings.
func TestProviderNetsReturnsCopy(t *testing.T) {
	// Ensure non-empty state from embedded snapshot.
	if err := LoadCache("/nonexistent/mailranges.json"); err != nil {
		t.Fatalf("LoadCache: %v", err)
	}

	nets1 := ProviderNets()
	if len(nets1) == 0 {
		t.Fatal("expected non-empty ProviderNets() for copy test")
	}

	// Capture the original CIDR strings before mutation.
	origStrings := make(map[string]bool, len(nets1))
	for _, n := range nets1 {
		origStrings[n.String()] = true
	}

	// Mutate every byte of every returned net's IP - this must not reach the store.
	for _, n := range nets1 {
		for i := range n.IP {
			n.IP[i] ^= 0xFF
		}
		for i := range n.Mask {
			n.Mask[i] ^= 0xFF
		}
	}

	// Second call must still return the original CIDRs.
	nets2 := ProviderNets()
	if len(nets2) != len(nets1) {
		t.Fatalf("want %d nets after mutation, got %d", len(nets1), len(nets2))
	}
	for _, n := range nets2 {
		if !origStrings[n.String()] {
			t.Errorf("net %s in second call does not match original set", n)
		}
	}
}
