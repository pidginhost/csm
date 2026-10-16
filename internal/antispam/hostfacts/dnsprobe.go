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

// QueryDNS asks server for the A and AAAA records of name, as an absolute
// name, and returns the answer without error text.
func QueryDNS(ctx context.Context, server netip.AddrPort, name string) antispam.ProbeAnswer {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, server.String())
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
