// Package clientaddr resolves the client address of an HTTP request or
// access-log record from its direct peer and X-Forwarded-For chain. The
// domlog scan and the challenge server share it, so one configured trust
// list decides the address they act on.
package clientaddr

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/pidginhost/csm/internal/netutil"
)

// Bounds on a forwarded chain: the bytes of the whole header, and the hops
// the walk reads before it reaches the client. A chain over either is
// refused, never trimmed. Hops a client writes left of its own address are
// never read, so they cannot make it refused.
const (
	MaxHops       = 32
	MaxChainBytes = 4096
)

// Refusals. Each names why no address was resolved; none falls back to the
// proxy, whose address identifies a shared transport, not a client.
var (
	ErrPeer       = errors.New("direct peer is not an IP address")
	ErrNoChain    = errors.New("trusted proxy sent no forwarded chain")
	ErrMalformed  = errors.New("forwarded chain holds an unreadable hop")
	ErrTruncated  = errors.New("forwarded chain was cut before its client")
	ErrOverlong   = errors.New("forwarded chain exceeds 4 KiB or 32 hops before its client")
	ErrAllTrusted = errors.New("forwarded chain holds only trusted proxies")
)

// Trusted is a parsed trusted proxy list.
type Trusted struct {
	prefixes []netip.Prefix
}

// Parse reads trusted proxy entries: IP addresses or CIDR ranges. An empty
// entry, a default route or anything else is an error naming its index.
func Parse(entries []string) (Trusted, error) {
	var t Trusted
	for i, raw := range entries {
		entry := strings.TrimSpace(raw)
		prefix, err := parseEntry(entry)
		if err != nil {
			return Trusted{}, fmt.Errorf("[%d]: %q %v", i, entry, err)
		}
		t.prefixes = append(t.prefixes, prefix)
	}
	return t, nil
}

func parseEntry(entry string) (netip.Prefix, error) {
	if entry == "" {
		return netip.Prefix{}, errors.New("is empty")
	}
	var prefix netip.Prefix
	if strings.Contains(entry, "/") {
		p, err := netip.ParsePrefix(entry)
		if err != nil {
			return netip.Prefix{}, errors.New("is not an IP address or CIDR range")
		}
		prefix = p
	} else {
		addr, err := netip.ParseAddr(entry)
		if err != nil || addr.Zone() != "" {
			return netip.Prefix{}, errors.New("is not an IP address or CIDR range")
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	// Masking a broader mapped range first would erase its IPv4 identity
	// and silently leave the configured IPv4 proxies uncovered.
	if prefix.Addr().Is4In6() {
		if prefix.Bits() <= 96 {
			return netip.Prefix{}, errors.New("covers every IPv4 address")
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	if prefix.Bits() == 0 {
		return netip.Prefix{}, errors.New("is a default route and would trust every address")
	}
	return prefix.Masked(), nil
}

// Len reports how many entries the list holds.
func (t Trusted) Len() int { return len(t.prefixes) }

// Covers reports whether addr is inside a configured entry, trusted or not.
// A listed address names a shared transport even where Has refuses to trust
// its header, so callers never read it as a client.
func (t Trusted) Covers(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range t.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Has reports whether addr is a trusted proxy whose header may be read:
// inside a configured entry and not an address of this host. Any local
// account can connect from a host address and write X-Forwarded-For, so such
// an entry is never trusted; an unread interface set trusts nobody.
func (t Trusted) Has(addr netip.Addr) bool {
	if !t.Covers(addr) {
		return false
	}
	local, known := netutil.IsHostLocal(net.IP(addr.Unmap().AsSlice()))
	return known && !local
}

// Result is a resolved client. Chained is true when the client came from a
// forwarded chain behind a trusted peer; then Peer is that proxy.
type Result struct {
	Client  netip.Addr
	Peer    netip.Addr
	Chained bool
}

// Resolve returns the client behind peer. peer is the direct peer as a log or
// socket writes it, with or without a port and without whitespace; xff is the
// X-Forwarded-For value (several header lines joined with commas). Only HTTP
// spaces and tabs may surround a hop. complete is false when the log kept
// only its right end; that suffix must contain whole comma-delimited tokens,
// never a fragment of an address. An untrusted peer is the client and its xff
// is ignored. For a trusted peer the chain is read right to left past trusted
// hops to the first other address; an unreadable hop on the way refuses the
// chain rather than being skipped.
func Resolve(peer, xff string, complete bool, t Trusted) (Result, error) {
	p, ok := parsePeer(peer)
	if !ok {
		return Result{}, ErrPeer
	}
	if !t.Has(p) {
		return Result{Client: p, Peer: p}, nil
	}
	return chain(p, xff, complete, t)
}

// ResolveBehindProxy returns the client behind a peer that has no address
// but is trusted by how it connects, such as a proxy on a Unix socket only
// its group can open. Its chain is read as Resolve reads a trusted peer's.
func ResolveBehindProxy(xff string, t Trusted) (Result, error) {
	return chain(netip.Addr{}, xff, true, t)
}

func chain(p netip.Addr, xff string, complete bool, t Trusted) (Result, error) {
	if len(xff) > MaxChainBytes {
		return Result{}, ErrOverlong
	}
	if strings.Trim(xff, " \t") == "" {
		return Result{}, ErrNoChain
	}
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		if len(hops)-i > MaxHops {
			return Result{}, ErrOverlong
		}
		hop, err := netip.ParseAddr(strings.Trim(hops[i], " \t"))
		if err != nil || hop.Zone() != "" {
			return Result{}, ErrMalformed
		}
		hop = hop.Unmap()
		if t.Has(hop) {
			continue
		}
		return Result{Client: hop, Peer: p, Chained: true}, nil
	}
	// The hops a log cut lie left of every hop read, so they matter only
	// when no client was found right of them.
	if !complete {
		return Result{}, ErrTruncated
	}
	return Result{}, ErrAllTrusted
}

// parsePeer reads a bare address, an address with a port, or a bracketed
// IPv6 address, and returns it unmapped. Zoned addresses, unmatched brackets
// and bracketed IPv4 are refused. Ports use the unpadded decimal spelling
// emitted by sockets and web servers.
func parsePeer(peer string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(peer)
	if err != nil {
		if ap, perr := netip.ParseAddrPort(peer); perr == nil {
			port := peer[strings.LastIndexByte(peer, ':')+1:]
			if len(port) > 1 && port[0] == '0' {
				return netip.Addr{}, false
			}
			addr = ap.Addr()
		} else if inner, ok := strings.CutPrefix(peer, "["); ok && strings.HasSuffix(inner, "]") {
			addr, err = netip.ParseAddr(strings.TrimSuffix(inner, "]"))
			if err != nil || !addr.Is6() {
				return netip.Addr{}, false
			}
		} else {
			return netip.Addr{}, false
		}
	}
	if addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
