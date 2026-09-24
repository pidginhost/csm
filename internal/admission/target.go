package admission

import (
	"net/netip"
	"strconv"
	"strings"
)

// Proto is the transport of a service target.
type Proto uint8

const (
	ProtoTCP Proto = iota + 1
	ProtoUDP
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	}
	return "proto(" + strconv.Itoa(int(p)) + ")"
}

// ParseProto accepts exactly "tcp" or "udp".
func ParseProto(s string) (Proto, error) {
	switch s {
	case "tcp":
		return ProtoTCP, nil
	case "udp":
		return ProtoUDP, nil
	}
	return 0, refuse(ReasonInvalid, "unknown transport")
}

// Service is a (transport, port) tuple. The zero value means no service.
type Service struct {
	Proto Proto
	Port  uint16
}

func (s Service) IsZero() bool { return s == Service{} }

// Caps is the firewall's address capability at canonicalization time.
type Caps struct {
	IPv6 bool
}

// Target is a canonical response target: one address, one prefix, or one
// service on one address. Construct it only through CanonicalAddress,
// CanonicalPrefix, CanonicalService or ParseTargetKey; the zero value is no
// target.
type Target struct {
	prefix  netip.Prefix
	service Service
}

// protectedPrefixes are never a target or part of one: unspecified,
// loopback, link-local, multicast and the limited broadcast address. The
// firewall engine refuses its own interface and infra addresses separately.
var protectedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/32"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func (t Target) IsZero() bool { return !t.prefix.IsValid() }

// Prefix returns the masked prefix; a single address has full length.
func (t Target) Prefix() netip.Prefix { return t.prefix }

// IsAddress reports whether t names exactly one address.
func (t Target) IsAddress() bool { return t.prefix.IsValid() && t.prefix.IsSingleIP() }

// Addr returns the address of a single-address or service target.
func (t Target) Addr() (netip.Addr, bool) {
	if !t.IsAddress() {
		return netip.Addr{}, false
	}
	return t.prefix.Addr(), true
}

// Service returns the service of a service target.
func (t Target) Service() (Service, bool) { return t.service, !t.service.IsZero() }

// Covers reports whether every address of u lies inside t.
func (t Target) Covers(u Target) bool {
	return t.prefix.IsValid() && u.prefix.IsValid() &&
		t.prefix.Bits() <= u.prefix.Bits() && t.prefix.Contains(u.prefix.Addr())
}

// Key is the canonical, reversible text form of t:
//
//	ip:192.0.2.1
//	net:198.51.100.0/24
//	svc:2001:db8::1/tcp/22
func (t Target) Key() string {
	switch {
	case t.IsZero():
		return ""
	case !t.service.IsZero():
		return "svc:" + t.prefix.Addr().String() + "/" + t.service.Proto.String() + "/" + strconv.Itoa(int(t.service.Port))
	case t.IsAddress():
		return "ip:" + t.prefix.Addr().String()
	}
	return "net:" + t.prefix.String()
}

func checkFamily(addr netip.Addr, caps Caps) error {
	if addr.Is6() && !caps.IPv6 {
		return refuse(ReasonUnsupportedContainment, "IPv6 is not enabled in the firewall")
	}
	return nil
}

// CanonicalAddress parses one address. IPv4-mapped IPv6 is unmapped; zones,
// protected addresses and IPv6 without firewall support are refused.
func CanonicalAddress(raw string, caps Caps) (Target, error) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return Target{}, refuse(ReasonInvalid, "address does not parse")
	}
	if addr.Zone() != "" {
		return Target{}, refuse(ReasonInvalid, "address carries a zone")
	}
	addr = addr.Unmap()
	for _, p := range protectedPrefixes {
		if p.Contains(addr) {
			return Target{}, refuse(ReasonProtected, "unspecified, loopback, link-local, multicast or broadcast address")
		}
	}
	if err := checkFamily(addr, caps); err != nil {
		return Target{}, err
	}
	return Target{prefix: netip.PrefixFrom(addr, addr.BitLen())}, nil
}

// CanonicalPrefix parses one CIDR prefix and masks its host bits. A prefix
// that overlaps a protected range, the default route, or a mapped prefix
// reaching outside IPv4 is refused.
func CanonicalPrefix(raw string, caps Caps) (Target, error) {
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		return Target{}, refuse(ReasonInvalid, "prefix does not parse")
	}
	addr, bits := p.Addr(), p.Bits()
	if addr.Is4In6() {
		if bits < 96 {
			return Target{}, refuse(ReasonInvalid, "mapped prefix reaches outside IPv4")
		}
		addr, bits = addr.Unmap(), bits-96
	}
	p = netip.PrefixFrom(addr, bits).Masked()
	if bits == 0 {
		return Target{}, refuse(ReasonProtected, "default route")
	}
	for _, protected := range protectedPrefixes {
		if protected.Overlaps(p) {
			return Target{}, refuse(ReasonProtected, "prefix overlaps an unspecified, loopback, link-local, multicast or broadcast range")
		}
	}
	if err := checkFamily(addr, caps); err != nil {
		return Target{}, err
	}
	return Target{prefix: p}, nil
}

// CanonicalService parses one service on one address. The port must be
// 1-65535 and the transport tcp or udp.
func CanonicalService(rawAddr, proto string, port int, caps Caps) (Target, error) {
	t, err := CanonicalAddress(rawAddr, caps)
	if err != nil {
		return Target{}, err
	}
	p, err := ParseProto(proto)
	if err != nil {
		return Target{}, err
	}
	if port < 1 || port > 65535 {
		return Target{}, refuse(ReasonInvalid, "port outside 1-65535")
	}
	t.service = Service{Proto: p, Port: uint16(port)}
	return t, nil
}

// ParseTargetKey parses a Key. Anything but the exact canonical form is
// refused, so a stored key cannot alias another target.
func ParseTargetKey(key string, caps Caps) (Target, error) {
	kind, rest, ok := strings.Cut(key, ":")
	if !ok {
		return Target{}, refuse(ReasonInvalid, "target key has no kind")
	}
	var t Target
	var err error
	switch kind {
	case "ip":
		t, err = CanonicalAddress(rest, caps)
	case "net":
		t, err = CanonicalPrefix(rest, caps)
	case "svc":
		portAt := strings.LastIndexByte(rest, '/')
		if portAt < 0 {
			return Target{}, refuse(ReasonInvalid, "service key has no port")
		}
		protoAt := strings.LastIndexByte(rest[:portAt], '/')
		if protoAt < 0 {
			return Target{}, refuse(ReasonInvalid, "service key has no transport")
		}
		port, perr := strconv.Atoi(rest[portAt+1:])
		if perr != nil {
			return Target{}, refuse(ReasonInvalid, "service key port is not a number")
		}
		t, err = CanonicalService(rest[:protoAt], rest[protoAt+1:portAt], port, caps)
	default:
		return Target{}, refuse(ReasonInvalid, "unknown target key kind")
	}
	if err != nil {
		return Target{}, err
	}
	if t.Key() != key {
		return Target{}, refuse(ReasonInvalid, "target key is not canonical")
	}
	return t, nil
}
