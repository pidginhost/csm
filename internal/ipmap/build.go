// Package ipmap builds and writes the CSM IP map: one rspamd multimap file
// listing CSM's own evidence about sender addresses (feeds spec 6).
package ipmap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/netip"
	"slices"
	"strconv"
)

// Symbol is one CSM_IP symbol and its multiplier on RuleScore.
type Symbol struct {
	Name       string
	Multiplier float64
}

// The CSM_IP rule's symbols, strongest first (spec 6.1). rspamd scores a
// symbol not in the rule's list at the rule's full score, so the writer
// emits only these.
var (
	Drop        = Symbol{"CSM_IP_DROP", 0.8}
	Blocked     = Symbol{"CSM_IP_BLOCKED", 0.6}
	MailAuth    = Symbol{"CSM_IP_MAIL_AUTH", 0.6}
	Spam        = Symbol{"CSM_IP_SPAM", 0.6}
	BlocklistDE = Symbol{"CSM_IP_BLOCKLISTDE", 0.4}
	CINS        = Symbol{"CSM_IP_CINS", 0.4}
	Canary      = Symbol{"CSM_IP_CANARY", 0}
)

// Symbols lists the rule's symbols in rule order.
func Symbols() []Symbol { return []Symbol{Drop, Blocked, MailAuth, Spam, BlocklistDE, CINS, Canary} }

const (
	// RuleScore is the CSM_IP rule's score; each line scales it.
	RuleScore = 5.0
	// CanaryAddr is the documentation address of the canary line.
	CanaryAddr = "192.0.2.255"
	// DefaultPath is where rspamd reads the map.
	DefaultPath = "/var/lib/csm-rspamd/csm_ip.map"
)

// Tenths is the symbol's score in Exim's integer tenths.
func (s Symbol) Tenths() int { return int(math.Round(RuleScore * s.Multiplier * 10)) }

func rank(name string) int {
	return slices.IndexFunc(Symbols(), func(s Symbol) bool { return s.Name == name })
}

// Sources are the entries per symbol name (addresses or CIDRs) and the
// addresses that must never be listed: whitelisted and the host's own.
type Sources struct {
	Entries map[string][]string
	Never   []netip.Addr
}

type entry struct {
	prefix netip.Prefix
	symbol Symbol
}

// Map is one built map: its lines and a most-specific-match lookup.
type Map struct {
	lines []entry
	exact map[netip.Addr]Symbol
	nets  []entry // longest prefix first
}

var canaryAddr = netip.MustParseAddr(CanaryAddr)

// Include both the non-listable ranges and the reserved canary. Check
// overlap too: a listable network address can still contain private hosts.
var excludedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/32"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.PrefixFrom(canaryAddr, canaryAddr.BitLen()),
}

// listable reports whether a can ever be listed: global unicast, not
// private, and not the canary, which only the canary line names.
func listable(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && a != canaryAddr
}

// Build makes the map from src: one line per address or network, with the
// strongest symbol winning and excluded addresses omitted. A nested address
// or network is kept only when its symbol is stronger, because rspamd uses
// the most specific match (spec 6.1).
func Build(src Sources) Map {
	never := make([]netip.Addr, len(src.Never))
	for i, a := range src.Never {
		never[i] = a.WithZone("").Unmap()
	}
	best := map[netip.Prefix]Symbol{}
	for _, s := range Symbols() {
		if s == Canary {
			continue
		}
		for _, raw := range src.Entries[s.Name] {
			p, ok := parse(raw)
			if !ok || !listable(p.Addr()) {
				continue
			}
			if slices.ContainsFunc(excludedNetworks, p.Overlaps) || slices.ContainsFunc(never, p.Contains) {
				continue
			}
			if cur, ok := best[p]; !ok || rank(s.Name) < rank(cur.Name) {
				best[p] = s
			}
		}
	}
	m := Map{exact: map[netip.Addr]Symbol{}}
	var nets []entry
	for p, s := range best {
		if !p.IsSingleIP() {
			nets = append(nets, entry{p, s})
		}
	}
	// Check every ancestor: the nearest one may itself be removed because
	// a broader network has a stronger symbol.
	covered := func(p netip.Prefix, s Symbol) bool {
		for _, n := range nets {
			if n.prefix.Bits() < p.Bits() && n.prefix.Contains(p.Addr()) && rank(n.symbol.Name) <= rank(s.Name) {
				return true
			}
		}
		return false
	}
	for p, s := range best {
		if covered(p, s) {
			continue
		}
		m.lines = append(m.lines, entry{p, s})
		if p.IsSingleIP() {
			m.exact[p.Addr()] = s
		} else {
			m.nets = append(m.nets, entry{p, s})
		}
	}
	slices.SortFunc(m.lines, func(a, b entry) int {
		if c := a.prefix.Addr().Compare(b.prefix.Addr()); c != 0 {
			return c
		}
		return a.prefix.Bits() - b.prefix.Bits()
	})
	slices.SortFunc(m.nets, func(a, b entry) int { return b.prefix.Bits() - a.prefix.Bits() })
	return m
}

// parse reads one address or network. A zoned IPv6 address is refused:
// netip keeps any text after the zone separator, newlines included, and the
// map is a line-oriented file.
func parse(raw string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(raw); err == nil {
		// Keep IPv4 entries in the same form as sender lookups and exclusions.
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, false
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(raw)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}

// Len is the number of data lines.
func (m Map) Len() int { return len(m.lines) }

// Weight is the score in tenths rspamd gives a, from its most specific
// entry; 0 when unlisted.
func (m Map) Weight(a netip.Addr) int {
	a = a.Unmap()
	if s, ok := m.exact[a]; ok {
		return s.Tenths()
	}
	for _, n := range m.nets {
		if n.prefix.Contains(a) {
			return n.symbol.Tenths()
		}
	}
	return 0
}

// Render returns the file and its generation: the first 12 hex digits of
// the SHA-256 of the data lines, which the canary line carries.
func (m Map) Render() ([]byte, string) {
	var data bytes.Buffer
	for _, e := range m.lines {
		target := e.prefix.String()
		if e.prefix.IsSingleIP() {
			target = e.prefix.Addr().String()
		}
		data.WriteString(target + " " + e.symbol.Name + ":" + strconv.FormatFloat(e.symbol.Multiplier, 'f', -1, 64) + "\n")
	}
	sum := sha256.Sum256(data.Bytes())
	gen := hex.EncodeToString(sum[:])[:12]
	var out bytes.Buffer
	out.WriteString(CanaryAddr + " " + Canary.Name + ":0:g" + gen + "\n")
	out.Write(data.Bytes())
	return out.Bytes(), gen
}
