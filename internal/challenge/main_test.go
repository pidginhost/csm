package challenge

import (
	"net"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/netutil"
)

// testHostAddr is the only interface address tests see unless one re-pins
// the lookup, so host-local trust decisions never depend on the machine
// running the tests.
const testHostAddr = "203.0.113.250"

func TestMain(m *testing.M) {
	restore := netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return []net.IP{net.ParseIP(testHostAddr)}, nil
	})
	code := m.Run()
	restore()
	os.Exit(code)
}
