package sharedsenders

import (
	"context"
	"net"
	"testing"
)

// A combined lookup can return the other family's answer and hide the
// failure in the family that could actually confirm the sender.
type partialForwardDNS struct {
	fakeResolver
	family string
	other  net.IP
}

func (r *partialForwardDNS) LookupIP(_ context.Context, network, host string) ([]net.IP, error) {
	if network == "ip" {
		return []net.IP{r.other}, nil
	}
	if network == r.family {
		return nil, &net.DNSError{Err: "server misbehaving", Name: host, IsTemporary: true}
	}
	return []net.IP{r.other}, nil
}

func TestSharedDoesNotLoseAddressFamilyFailure(t *testing.T) {
	for _, tc := range []struct{ ip, family, other string }{
		{"203.0.113.7", "ip4", "2001:db8::7"},
		{"2001:db8::7", "ip6", "203.0.113.7"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			r := &partialForwardDNS{
				fakeResolver: fakeResolver{ptr: map[string][]string{tc.ip: {"mx.mail.example.net."}}},
				family:       tc.family, other: net.ParseIP(tc.other),
			}
			if !ptrGuard().Shared(context.Background(), r, addr(tc.ip), testNow) {
				t.Fatal("an incomplete forward lookup allowed a spam report")
			}
		})
	}
}

func TestLoadRejectsEmptyProviderPolicy(t *testing.T) {
	c := validCache()
	p := c.Providers["google"]
	p.Nets, p.PTR = nil, nil
	c.Providers["google"] = p
	g := New(writeCache(t, mustJSON(t, c)))
	if err := g.Load(testNow); err == nil {
		t.Fatal("accepted a provider without any sender policy")
	}
	if g.Ready(testNow) || !g.Covers(addr("198.51.100.7"), testNow) {
		t.Fatal("an empty provider policy allowed spam reports")
	}
}
