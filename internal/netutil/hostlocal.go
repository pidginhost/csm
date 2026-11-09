package netutil

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// staticHostLocal lists the ranges every process on a host can send from
// without looking at its interfaces: loopback and the unspecified addresses.
var staticHostLocal = []struct {
	prefix netip.Prefix
	label  string
}{
	{netip.MustParsePrefix("127.0.0.0/8"), "127.0.0.0/8"},
	{netip.MustParsePrefix("::1/128"), "::1"},
	{netip.MustParsePrefix("0.0.0.0/32"), "0.0.0.0"},
	{netip.MustParsePrefix("::/128"), "::"},
	// Prefixes shorter than /96 can cover mapped IPv4 without having a
	// mapped network address. Every such range contains mapped loopback.
	{netip.MustParsePrefix("::ffff:127.0.0.0/104"), "127.0.0.0/8"},
}

// The host-local cache keeps the last interface set that was read, unlike the
// IsHostAddress cache: callers deciding whether to trust a peer must not fall
// back to "not local" because one refresh failed. Guarded by hostAddrMu.
var (
	hostLocalCache        map[netip.Addr]struct{}
	hostLocalCachedAt     time.Time
	hostLocalCacheGood    bool
	hostLocalNextLookup   uint64
	hostLocalCachedLookup uint64
)

// IsHostLocal reports whether ip is an address a process on this host can
// connect from: loopback, unspecified, or bound to one of its interfaces,
// link-local included. known is false only when the interface set has never
// been read, so a caller deciding trust can refuse rather than guess.
// Failed or out-of-order refreshes preserve the most recent successful set.
func IsHostLocal(ip net.IP) (local, known bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false, false
	}
	addr = addr.Unmap()
	if isStaticHostLocal(addr) {
		return true, true
	}
	set, ok := hostLocalAddrs()
	if !ok {
		return false, false
	}
	_, found := set[addr]
	return found, true
}

// HostLocalProxyEntry returns the first trusted-proxy entry that equals,
// contains or overlaps an address of this host, and what it covers.
// Loopback and unspecified hits need no interface lookup; any other entry
// needs a fresh one, and a failed lookup is an error, not a pass.
// Overlaps include IPv4-mapped IPv6 ranges, even prefixes shorter than /96.
func HostLocalProxyEntry(entries []string) (entry, covered string, err error) {
	type parsed struct {
		raw    string
		prefix netip.Prefix
	}
	var rest []parsed
	for _, e := range entries {
		raw := strings.TrimSpace(e)
		p, ok := entryPrefix(raw)
		if !ok {
			continue
		}
		for _, s := range staticHostLocal {
			if p.Overlaps(s.prefix) {
				return raw, s.label, nil
			}
		}
		rest = append(rest, parsed{raw, p})
	}
	if len(rest) == 0 {
		return "", "", nil
	}
	hostAddrMu.Lock()
	lookup := hostAddrLookup
	hostAddrMu.Unlock()
	ips, err := lookup()
	if err != nil {
		return "", "", fmt.Errorf("reading this host's addresses: %w", err)
	}
	host := hostLocalSet(ips)
	addrs := make([]netip.Addr, 0, len(host))
	for a := range host {
		addrs = append(addrs, a)
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	for _, p := range rest {
		for _, a := range addrs {
			if p.prefix.Contains(a) {
				return p.raw, a.String(), nil
			}
		}
	}
	return "", "", nil
}

func isStaticHostLocal(addr netip.Addr) bool {
	for _, s := range staticHostLocal {
		if s.prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// entryPrefix parses an address or CIDR the way trusted-proxy lists do.
func entryPrefix(raw string) (netip.Prefix, bool) {
	n := ParseCIDROrIP(raw)
	if n == nil {
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, false
	}
	if addr.Is4In6() && bits == 128 {
		if ones < 96 {
			return netip.Prefix{}, false
		}
		ones -= 96
	}
	addr = addr.Unmap()
	p, err := addr.Prefix(ones)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

func hostLocalSet(ips []net.IP) map[netip.Addr]struct{} {
	set := make(map[netip.Addr]struct{}, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			set[a.Unmap()] = struct{}{}
		}
	}
	return set
}

func hostLocalAddrs() (map[netip.Addr]struct{}, bool) {
	hostAddrMu.Lock()
	if hostLocalCacheGood && time.Since(hostLocalCachedAt) < hostAddrCacheTTL {
		set := hostLocalCache
		hostAddrMu.Unlock()
		return set, true
	}
	lookup, generation := hostAddrLookup, hostAddrGeneration
	hostLocalNextLookup++
	lookupID := hostLocalNextLookup
	hostAddrMu.Unlock()

	ips, err := lookup()

	hostAddrMu.Lock()
	defer hostAddrMu.Unlock()
	// A lookup swapped in meanwhile owns the cache; never let this one
	// repopulate it.
	if err != nil || generation != hostAddrGeneration {
		return hostLocalCache, hostLocalCacheGood
	}
	// A slower, earlier lookup must not discard addresses discovered by a
	// later one, even if that newer result has since expired.
	if lookupID < hostLocalCachedLookup {
		return hostLocalCache, hostLocalCacheGood
	}
	hostLocalCache = hostLocalSet(ips)
	hostLocalCachedAt = time.Now()
	hostLocalCacheGood = true
	hostLocalCachedLookup = lookupID
	return hostLocalCache, true
}
