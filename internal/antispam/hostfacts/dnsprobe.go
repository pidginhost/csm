package hostfacts

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

// probeTimeout bounds one probe query (feeds spec section 8.3).
const probeTimeout = 3 * time.Second

// dnsPort is the resolver port; tests point it at a local server.
var dnsPort uint16 = 53

// QueryDNS asks server for the A and AAAA records of name, as an absolute
// name, and returns the answer without error text.
func QueryDNS(ctx context.Context, server netip.Addr, name string) antispam.ProbeAnswer {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, netip.AddrPortFrom(server, dnsPort).String())
	}}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	addrs, err := r.LookupHost(ctx, name+".")
	var dnsErr *net.DNSError
	switch {
	case err == nil:
		return antispam.ProbeAnswer{Addrs: addrs}
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return antispam.ProbeAnswer{NXDomain: true}
	}
	return antispam.ProbeAnswer{Failed: true}
}
