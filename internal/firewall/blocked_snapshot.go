package firewall

import "net"

// LiveBlockedSnapshot is a point-in-time membership view of the kernel's
// blocked IP sets, taken in one netlink round trip.
//
// HasV4 / HasV6 record which families the snapshot actually covers. A set can
// be absent -- firewall.ipv6 disabled leaves the v6 set nil -- and an
// uncovered family must never read as "not blocked", or a reconcile pass
// would prune every tracked block of that family on its first cycle.
type LiveBlockedSnapshot struct {
	V4    map[string]struct{}
	V6    map[string]struct{}
	HasV4 bool
	HasV6 bool
}

// Contains reports whether ip is in the live blocked set. known is false when
// the snapshot does not cover the IP's address family, in which case the
// caller must keep its cached answer rather than treat ip as unblocked.
//
// Family selection mirrors the per-IP path: an IPv4-mapped IPv6 address
// resolves against the v4 set, because that is the set the block path keys it
// into. A malformed IP is reported as definitively absent, matching
// IsBlockedLive.
func (s LiveBlockedSnapshot) Contains(ip string) (blocked, known bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, true
	}
	if v4 := parsed.To4(); v4 != nil {
		if !s.HasV4 {
			return false, false
		}
		_, ok := s.V4[v4.String()]
		return ok, true
	}
	if !s.HasV6 {
		return false, false
	}
	_, ok := s.V6[parsed.To16().String()]
	return ok, true
}
