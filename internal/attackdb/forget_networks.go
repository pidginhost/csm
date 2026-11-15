package attackdb

import (
	"net"
	"net/netip"

	"github.com/pidginhost/csm/internal/netutil"
)

// ForgetNetworks removes scoring records inside the supplied networks and
// returns the number removed. A network record goes when it shares any
// address with one of them. Event history is retained. Scanning once under
// the lock avoids a full database scan per address during startup cleanup.
func (db *DB) ForgetNetworks(nets []*net.IPNet) int {
	if len(nets) == 0 {
		return 0
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	dropped := 0
	for key := range db.records {
		if netutil.IPInAnyNet(net.ParseIP(key), nets) || isNetworkKey(key) && networkKeyOverlaps(key, nets) {
			delete(db.records, key)
			db.markDeletedLocked(key)
			dropped++
		}
	}
	return dropped
}

func networkKeyOverlaps(key string, nets []*net.IPNet) bool {
	network, err := netip.ParsePrefix(key)
	if err != nil {
		return false
	}
	for _, n := range nets {
		addr, _ := netip.AddrFromSlice(n.IP)
		addr = addr.Unmap()
		// A mask that does not fit the address would read as a /0 and match all.
		if ones, bits := n.Mask.Size(); bits == addr.BitLen() && network.Overlaps(netip.PrefixFrom(addr, ones)) {
			return true
		}
	}
	return false
}
