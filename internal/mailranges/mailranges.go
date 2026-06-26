// Package mailranges maintains an atomic in-memory map of mail-provider IP
// ranges used to exempt shared-source ranges (carrier CGNAT, mail providers)
// from firewall DoS heuristics. The package is self-contained: it embeds a
// seed snapshot so the binary ships with a usable fallback and holds no
// references to any identity-verification or bot-allowlist logic.
package mailranges

import (
	_ "embed"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// embeddedSnapshot is the seed snapshot compiled into the binary. It contains
// a handful of real Google and Microsoft outbound-mail CIDRs as placeholders.
// Task 6, Step 5 replaces this file with resolver-generated content so the
// shipped binary always carries a current snapshot.
//
//go:embed snapshot.json
var embeddedSnapshot []byte

// cacheFile is the shared JSON schema for both the on-disk cache and the
// embedded snapshot. The same decoder handles both paths.
type cacheFile struct {
	RefreshedAt int64               `json:"refreshed_at"`
	Providers   map[string][]string `json:"providers"`
}

// providerMap is the concrete type stored in providerAtom. atomic.Value
// requires the same concrete type on every Store call; a named type satisfies
// that without an extra allocation.
type providerMap map[string][]*net.IPNet

var (
	providerAtom  atomic.Value // stores providerMap; nil load = never published
	lastRefreshAt atomic.Int64 // Unix timestamp; 0 = never published
)

// PublishProviderSnapshot installs a new provider snapshot atomically. The
// input is deep-copied before storing so callers may modify m after returning.
// A nil or empty m publishes an empty map (clears the effective set).
func PublishProviderSnapshot(m map[string][]*net.IPNet) {
	cp := make(providerMap, len(m))
	for k, v := range m {
		nets := make([]*net.IPNet, len(v))
		for i, n := range v {
			nets[i] = cloneIPNet(n)
		}
		cp[k] = nets
	}
	providerAtom.Store(cp)
}

// ProviderNets returns a flat slice of all current provider nets across every
// provider. Each call returns a freshly allocated deep copy so callers may
// inspect or modify the slice and its elements without affecting the store.
func ProviderNets() []*net.IPNet {
	m := loadProviderMap()
	var out []*net.IPNet
	for _, nets := range m {
		for _, n := range nets {
			out = append(out, cloneIPNet(n))
		}
	}
	return out
}

// ProviderSnapshot returns the current provider map as a deep copy keyed by
// provider name. The returned map and its *net.IPNet values are independent of
// the atomic store; mutations do not propagate back.
func ProviderSnapshot() map[string][]*net.IPNet {
	m := loadProviderMap()
	out := make(map[string][]*net.IPNet, len(m))
	for k, v := range m {
		nets := make([]*net.IPNet, len(v))
		for i, n := range v {
			nets[i] = cloneIPNet(n)
		}
		out[k] = nets
	}
	return out
}

// LastRefresh returns when PublishProviderSnapshot was last called (via
// LoadCache or an external refresh), or the zero time if it never has been.
func LastRefresh() time.Time {
	ts := lastRefreshAt.Load()
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}

// LoadCache reads the on-disk provider range cache at path and publishes it.
// On any read or parse failure it falls back to embeddedSnapshot. If both
// the on-disk cache and the embedded snapshot fail to parse, LoadCache
// publishes an empty provider map and returns the error so the caller can log
// it. A missing file is a normal first-run condition and is not an error when
// the embedded snapshot parses successfully.
func LoadCache(path string) error {
	data, readErr := os.ReadFile(path) // #nosec G304 -- daemon-owned state path
	if readErr == nil {
		m, ts, err := parseCacheData(data)
		if err == nil {
			PublishProviderSnapshot(m)
			lastRefreshAt.Store(ts)
			return nil
		}
		// on-disk cache unreadable; fall through to embedded snapshot
	}

	m, ts, embErr := parseCacheData(embeddedSnapshot)
	if embErr != nil {
		// Both sources failed; publish an empty map so readers get a safe zero value.
		PublishProviderSnapshot(nil)
		return embErr
	}
	PublishProviderSnapshot(m)
	lastRefreshAt.Store(ts)
	return nil
}

// parseCacheData decodes the shared cacheFile JSON format into a provider map.
// Malformed entries make the whole cache unusable so LoadCache can fall back to
// the embedded snapshot instead of publishing a narrowed partial set.
func parseCacheData(data []byte) (map[string][]*net.IPNet, int64, error) {
	var c cacheFile
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, 0, err
	}
	m := make(map[string][]*net.IPNet, len(c.Providers))
	total := 0
	for provider, strs := range c.Providers {
		for _, s := range strs {
			_, n, err := net.ParseCIDR(strings.TrimSpace(s))
			if err != nil {
				return nil, 0, err
			}
			m[provider] = append(m[provider], n)
			total++
		}
	}
	if total == 0 {
		return nil, 0, errors.New("mailranges: cache has no usable provider prefixes")
	}
	return m, c.RefreshedAt, nil
}

func loadProviderMap() providerMap {
	v := providerAtom.Load()
	if v == nil {
		return nil
	}
	return v.(providerMap) //nolint:forcetypeassert -- only providerMap is ever stored
}

// cloneIPNet returns a deep copy of n. Both the IP and Mask byte slices are
// freshly allocated so mutations to the original do not affect the clone.
func cloneIPNet(n *net.IPNet) *net.IPNet {
	if n == nil {
		return nil
	}
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP)
	mask := make(net.IPMask, len(n.Mask))
	copy(mask, n.Mask)
	return &net.IPNet{IP: ip, Mask: mask}
}
