package netutil

import (
	"net"
	"testing"
	"time"
)

// SetHostAddressLookupForTest wraps SetHostAddressLookup with automatic
// restore so tests inside this package do not have to defer by hand.
func SetHostAddressLookupForTest(t *testing.T, fn func() ([]net.IP, error)) {
	t.Helper()
	t.Cleanup(SetHostAddressLookup(fn))
}

func expireHostAddressCacheForTest(at time.Time) {
	hostAddrMu.Lock()
	hostAddrCachedAt = at
	hostAddrMu.Unlock()
}
