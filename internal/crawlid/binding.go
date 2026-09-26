package crawlid

import (
	"encoding/base64"
	"net/netip"
)

// Binding is the client unit a token and the detector's distribution tests
// use: the full IPv4 address, or the IPv6 /64. IPv4-mapped IPv6 is IPv4.
type Binding string

// BindingOf parses a textual client address. Zone-scoped, malformed or
// port-suffixed input is rejected.
func BindingOf(ip string) (Binding, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Zone() != "" {
		return "", false
	}
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return Binding("4" + string(b[:])), true
	}
	b := a.As16()
	return Binding("6" + string(b[:8])), true
}

// String is the unpadded base64url form used in JSON and vectors.
func (b Binding) String() string {
	return base64.RawURLEncoding.EncodeToString([]byte(b))
}
