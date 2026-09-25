package admission

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

var v6 = Caps{IPv6: true}

func wantReason(t *testing.T, what string, err error, want Reason) {
	t.Helper()
	if got, ok := ReasonOf(err); !ok || got != want {
		t.Errorf("%s: err = %v, want reason %s", what, err, want)
	}
}

func TestCanonicalAddress(t *testing.T) {
	accepted := map[string]string{
		"192.0.2.1":        "ip:192.0.2.1",
		"::ffff:192.0.2.1": "ip:192.0.2.1",
		"2001:db8::1":      "ip:2001:db8::1",
		"2001:DB8:0::0001": "ip:2001:db8::1",
		"203.0.113.255":    "ip:203.0.113.255",
	}
	for raw, key := range accepted {
		got, err := CanonicalAddress(raw, v6)
		if err != nil || got.Key() != key || !got.IsAddress() {
			t.Errorf("CanonicalAddress(%q) = %q %v, want %q", raw, got.Key(), err, key)
		}
	}
	refused := map[string]Reason{
		"":                 ReasonInvalid,
		"192.0.2":          ReasonInvalid,
		"010.0.0.1":        ReasonInvalid,
		"192.0.2.1/32":     ReasonInvalid,
		"fe80::1%eth0":     ReasonInvalid,
		"0.0.0.0":          ReasonProtected,
		"::":               ReasonProtected,
		"127.0.0.1":        ReasonProtected,
		"::1":              ReasonProtected,
		"::ffff:127.0.0.1": ReasonProtected,
		"169.254.10.1":     ReasonProtected,
		"fe80::1":          ReasonProtected,
		"224.0.0.251":      ReasonProtected,
		"239.1.2.3":        ReasonProtected,
		"ff02::1":          ReasonProtected,
		"ff0e::1":          ReasonProtected,
		"255.255.255.255":  ReasonProtected,
	}
	for raw, reason := range refused {
		_, err := CanonicalAddress(raw, v6)
		wantReason(t, "CanonicalAddress("+raw+")", err, reason)
	}
	for _, raw := range []string{" 192.0.2.1", "192.0.2.1\n"} {
		_, err := CanonicalAddress(raw, v6)
		wantReason(t, "address with whitespace", err, ReasonInvalid)
	}
	_, err := CanonicalAddress("2001:db8::1", Caps{})
	wantReason(t, "IPv6 without capability", err, ReasonUnsupportedContainment)
	if got, err := CanonicalAddress("::ffff:192.0.2.1", Caps{}); err != nil || got.Key() != "ip:192.0.2.1" {
		t.Errorf("a mapped IPv4 address needs no IPv6 capability: %q %v", got.Key(), err)
	}
}

func TestCanonicalPrefix(t *testing.T) {
	accepted := map[string]string{
		"198.51.100.7/24":         "net:198.51.100.0/24",
		"::ffff:198.51.100.0/120": "net:198.51.100.0/24",
		"203.0.113.0/25":          "net:203.0.113.0/25",
		"2001:db8::/32":           "net:2001:db8::/32",
		"198.51.100.1/32":         "ip:198.51.100.1",
	}
	for raw, key := range accepted {
		got, err := CanonicalPrefix(raw, v6)
		if err != nil || got.Key() != key {
			t.Errorf("CanonicalPrefix(%q) = %q %v, want %q", raw, got.Key(), err, key)
		}
	}
	refused := map[string]Reason{
		"198.51.100.0":      ReasonInvalid,
		"198.51.100.0/33":   ReasonInvalid,
		"fe80::/64%eth0":    ReasonInvalid,
		"::ffff:0.0.0.0/95": ReasonInvalid,
		"0.0.0.0/0":         ReasonProtected,
		"::/0":              ReasonProtected,
		"0.0.0.0/8":         ReasonProtected,
		"127.0.0.0/16":      ReasonProtected,
		"126.0.0.0/7":       ReasonProtected,
		"224.0.0.0/3":       ReasonProtected,
		"239.0.0.0/8":       ReasonProtected,
		"192.0.0.0/2":       ReasonProtected,
		"255.255.255.0/24":  ReasonProtected,
		"fe80::/64":         ReasonProtected,
		"ff00::/12":         ReasonProtected,
		"8000::/1":          ReasonProtected,
	}
	for raw, reason := range refused {
		_, err := CanonicalPrefix(raw, v6)
		wantReason(t, "CanonicalPrefix("+raw+")", err, reason)
	}
	_, err := CanonicalPrefix("2001:db8::/48", Caps{})
	wantReason(t, "IPv6 prefix without capability", err, ReasonUnsupportedContainment)
}

// A supernet of the mapped range cannot be unmapped as one IPv4 prefix.
// Non-mapped host bits must not let it bypass the mapped-prefix refusal.
func TestPrefixesSpanningMappedIPv4AreRefused(t *testing.T) {
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")
	for bits := 81; bits < 96; bits++ {
		network := netip.PrefixFrom(mapped, bits).Masked()
		for _, addr := range []netip.Addr{network.Addr(), network.Addr().Next(), mapped} {
			raw := addr.String() + "/" + strconv.Itoa(bits)
			t.Run(raw, func(t *testing.T) {
				for _, caps := range []Caps{{}, v6} {
					got, err := CanonicalPrefix(raw, caps)
					wantReason(t, "CanonicalPrefix", err, ReasonInvalid)
					if !got.IsZero() {
						t.Errorf("refused prefix returned target %q", got.Key())
					}
					got, err = ParseTargetKey("net:"+raw, caps)
					wantReason(t, "ParseTargetKey", err, ReasonInvalid)
					if !got.IsZero() {
						t.Errorf("refused key returned target %q", got.Key())
					}
				}
			})
		}
	}
}

func TestPrefixesAdjacentToMappedIPv4RemainNative(t *testing.T) {
	for _, raw := range []string{"::fffe:0:0/96", "::1:0:0:0/96"} {
		got, err := CanonicalPrefix(raw, v6)
		if err != nil || got.Key() != "net:"+raw || got.Prefix() != netip.MustParsePrefix(raw) {
			t.Fatalf("CanonicalPrefix(%q) = %q %v", raw, got.Key(), err)
		}
		again, err := ParseTargetKey(got.Key(), v6)
		if err != nil || again != got {
			t.Errorf("adjacent prefix does not round-trip: %q %v", again.Key(), err)
		}
		_, err = CanonicalPrefix(raw, Caps{})
		wantReason(t, "native prefix without capability", err, ReasonUnsupportedContainment)
	}
}

func TestCanonicalService(t *testing.T) {
	got, err := CanonicalService("::ffff:192.0.2.1", "tcp", 22, Caps{})
	if err != nil || got.Key() != "svc:192.0.2.1/tcp/22" {
		t.Fatalf("CanonicalService = %q %v", got.Key(), err)
	}
	if s, ok := got.Service(); !ok || s != (Service{ProtoTCP, 22}) {
		t.Errorf("Service() = %+v %v", s, ok)
	}
	if six, sixErr := CanonicalService("2001:db8::1", "udp", 65535, v6); sixErr != nil || six.Key() != "svc:2001:db8::1/udp/65535" {
		t.Errorf("IPv6 service = %q %v", six.Key(), sixErr)
	}
	for _, tc := range []struct {
		proto string
		port  int
	}{{"tcp", 0}, {"tcp", 65536}, {"tcp", -1}, {"TCP", 22}, {"sctp", 22}, {"", 22}} {
		_, svcErr := CanonicalService("192.0.2.1", tc.proto, tc.port, v6)
		wantReason(t, "service "+tc.proto, svcErr, ReasonInvalid)
	}
	_, err = CanonicalService("127.0.0.1", "tcp", 22, v6)
	wantReason(t, "service on loopback", err, ReasonProtected)
}

func TestAdmissionServiceTargetIsAddress(t *testing.T) {
	for _, raw := range []string{"192.0.2.1", "2001:db8::1"} {
		target := mustService(t, raw, "tcp", 22)
		if _, ok := target.Service(); !ok || !target.IsAddress() {
			t.Fatalf("service target %q must also be one address", target.Key())
		}
		if addr, ok := target.Addr(); !ok || addr.String() != raw {
			t.Fatalf("service address = %v %v, want %s", addr, ok, raw)
		}
	}
}

func TestParseTargetKeyRoundTripsAndRefusesAliases(t *testing.T) {
	for _, key := range []string{
		"ip:192.0.2.1", "ip:2001:db8::1", "net:198.51.100.0/24",
		"net:2001:db8::/32", "svc:192.0.2.1/tcp/22", "svc:2001:db8::1/udp/53",
	} {
		got, err := ParseTargetKey(key, v6)
		if err != nil || got.Key() != key {
			t.Errorf("ParseTargetKey(%q) = %q %v", key, got.Key(), err)
		}
	}
	for _, key := range []string{
		"", "192.0.2.1", "x:192.0.2.1", "ip:::ffff:192.0.2.1",
		"ip:192.0.2.1/32", "net:198.51.100.7/24", "net:198.51.100.1/32",
		"svc:192.0.2.1/tcp/022", "svc:192.0.2.1/tcp/+22", "svc:192.0.2.1/tcp",
		"svc:/tcp/22", "svc:192.0.2.1//22", "svc:[2001:db8::1]/tcp/22",
	} {
		_, err := ParseTargetKey(key, v6)
		wantReason(t, "ParseTargetKey("+key+")", err, ReasonInvalid)
	}
}

func TestTargetCovers(t *testing.T) {
	net24, _ := CanonicalPrefix("198.51.100.0/24", v6)
	inside, _ := CanonicalAddress("198.51.100.9", v6)
	outside, _ := CanonicalAddress("203.0.113.9", v6)
	net25, _ := CanonicalPrefix("198.51.100.128/25", v6)
	if !net24.Covers(inside) || !net24.Covers(net25) || !inside.Covers(inside) {
		t.Error("a prefix does not cover its own addresses")
	}
	if net24.Covers(outside) || net25.Covers(net24) || inside.Covers(net24) || (Target{}).Covers(inside) {
		t.Error("a target covers an address outside it")
	}
}

// Refusal text is written to status and audit. It must never echo the
// refused input, which an attacker may control.
func TestRefusalsNeverEchoInput(t *testing.T) {
	hostile := "<script>alert(1)</script>"
	for _, err := range []error{
		func() error { _, err := CanonicalAddress(hostile, v6); return err }(),
		func() error { _, err := CanonicalPrefix(hostile, v6); return err }(),
		func() error { _, err := CanonicalService("192.0.2.1", hostile, 22, v6); return err }(),
		func() error { _, err := ParseTargetKey("svc:"+hostile+"/tcp/22", v6); return err }(),
	} {
		if err == nil || strings.Contains(err.Error(), "script") {
			t.Errorf("refusal %v echoes its input", err)
		}
	}
}

func TestTransportValuesAreFrozen(t *testing.T) {
	for name, pair := range map[string][2]uint8{"ProtoTCP": {uint8(ProtoTCP), 1}, "ProtoUDP": {uint8(ProtoUDP), 2}} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %d, frozen at %d", name, pair[0], pair[1])
		}
	}
}
