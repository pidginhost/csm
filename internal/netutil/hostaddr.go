package netutil

import (
	"net"
	"sync"
	"time"
)

// hostAddrCacheTTL bounds how long a cached interface enumeration is reused.
// Alias IPs come and go on panel hosts, so the set cannot be read once at
// startup, but enumerating on every finding would be wasteful.
const hostAddrCacheTTL = 5 * time.Minute

// hostAddrLookup returns every IP bound to a local interface. Package-level so
// tests can inject deterministic addresses.
var hostAddrLookup = enumerateHostAddresses

var (
	hostAddrMu         sync.Mutex
	hostAddrCache      map[string]struct{}
	hostAddrCachedAt   time.Time
	hostAddrCacheGood  bool
	hostAddrGeneration uint64
)

func enumerateHostAddresses() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			out = append(out, v.IP)
		case *net.IPAddr:
			out = append(out, v.IP)
		}
	}
	return out, nil
}

// IsHostAddress reports whether ip is an address bound to one of this host's
// own interfaces.
//
// Traffic a machine sends to itself is not an attack on itself. cPanel hosts
// proxy nginx to Apache over the machine's public address rather than
// loopback, so without this guard every proxied request counts as inbound
// traffic from the server, and a site that answers its own cron with an error
// drives the host's own address up the local threat score.
//
// Loopback and link-local addresses deliberately do not count: callers that
// want to accept local traffic outright test for that separately, and folding
// it in here would let a check discard findings that really did originate on
// the box. A lookup failure fails open (reports false) so a transient syscall
// error cannot suppress every finding.
func IsHostAddress(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
		return false
	}
	set, ok := hostAddresses()
	if !ok {
		return false
	}
	_, found := set[hostAddrKey(parsed)]
	return found
}

// hostAddrKey normalizes an address so the v4-mapped-v6 and non-canonical
// textual forms of the same address share one key.
func hostAddrKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func hostAddresses() (map[string]struct{}, bool) {
	hostAddrMu.Lock()

	if hostAddrCacheGood && time.Since(hostAddrCachedAt) < hostAddrCacheTTL {
		set := hostAddrCache
		hostAddrMu.Unlock()
		return set, true
	}
	lookup, generation := hostAddrLookup, hostAddrGeneration
	hostAddrMu.Unlock()

	ips, err := lookup()
	if err != nil {
		return nil, false
	}
	set := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		set[hostAddrKey(ip)] = struct{}{}
	}
	hostAddrMu.Lock()
	defer hostAddrMu.Unlock()
	// Replacing the source invalidates any lookup already in flight. Never
	// let an old callback repopulate the replacement's cache.
	if generation != hostAddrGeneration {
		return nil, false
	}
	if hostAddrCacheGood && time.Since(hostAddrCachedAt) < hostAddrCacheTTL {
		return hostAddrCache, true
	}
	hostAddrCache = set
	hostAddrCachedAt = time.Now()
	hostAddrCacheGood = true
	return set, true
}

// SetHostAddressLookup swaps the interface enumeration and drops the cache,
// returning a function that restores the previous lookup. Tests in other
// packages use it to pin a deterministic address set.
func SetHostAddressLookup(fn func() ([]net.IP, error)) func() {
	hostAddrMu.Lock()
	prev := hostAddrLookup
	hostAddrLookup = fn
	hostAddrGeneration++
	hostAddrCache = nil
	hostAddrCacheGood = false
	hostAddrMu.Unlock()

	return func() {
		hostAddrMu.Lock()
		hostAddrLookup = prev
		hostAddrGeneration++
		hostAddrCache = nil
		hostAddrCacheGood = false
		hostAddrMu.Unlock()
	}
}
