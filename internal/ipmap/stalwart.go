package ipmap

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// StalwartNamespace is the lookup namespace holding s's keys for one address family.
func StalwartNamespace(s Symbol, v6 bool) string {
	ns := "csm-ip-"
	if v6 {
		ns = "csm-ip6-"
	}
	return ns + strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(s.Name, "CSM_IP_")), "_", "-")
}

// StalwartNamespaces lists every CSM namespace in rule order, IPv4 then IPv6 per symbol.
func StalwartNamespaces() []string {
	var out []string
	for _, s := range Symbols() {
		out = append(out, StalwartNamespace(s, false), StalwartNamespace(s, true))
	}
	return out
}

// StalwartKeys returns sorted keys in every namespace, with CanaryAddr in the IPv4 canary namespace.
func (m Map) StalwartKeys() map[string][]string {
	out := map[string][]string{}
	for _, ns := range StalwartNamespaces() {
		out[ns] = nil
	}
	out[StalwartNamespace(Canary, false)] = []string{CanaryAddr}
	for _, e := range m.lines {
		ns := StalwartNamespace(e.symbol, e.prefix.Addr().Is6())
		out[ns] = append(out[ns], stalwartKeys(e.prefix)...)
	}
	for _, keys := range out {
		slices.Sort(keys)
	}
	return out
}

// Masked prefixes split at the next octet or nibble boundary, varying only the last unit.
func stalwartKeys(p netip.Prefix) []string {
	a := p.Addr()
	var units []int
	width := 8
	if a.Is4() {
		for _, o := range a.As4() {
			units = append(units, int(o))
		}
	} else {
		width = 4
		for _, o := range a.As16() {
			units = append(units, int(o>>4), int(o&0xf))
		}
	}
	n := (p.Bits() + width - 1) / width
	var keys []string
	for i := range 1 << (n*width - p.Bits()) {
		u := slices.Clone(units[:n])
		u[n-1] += i
		keys = append(keys, stalwartKey(u, a.Is4(), n == len(units)))
	}
	return keys
}

func stalwartKey(units []int, v4, exact bool) string {
	parts := make([]string, len(units))
	if v4 {
		// IPv4 remote_ip is dotted text, so networks need forward globs instead of CIDRs.
		for i, u := range units {
			parts[i] = strconv.Itoa(u)
		}
		if exact {
			return strings.Join(parts, ".")
		}
		return strings.Join(parts, ".") + ".*"
	}
	// Compressed IPv6 text prevents forward globs, so keys use reversed nibble names.
	for i, u := range units {
		parts[len(units)-1-i] = strconv.FormatInt(int64(u), 16)
	}
	if exact {
		return strings.Join(parts, ".")
	}
	return "*." + strings.Join(parts, ".")
}
