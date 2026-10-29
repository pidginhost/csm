package attackdb

import (
	"net"

	"github.com/pidginhost/csm/internal/netutil"
)

// ForgetNetworks removes scoring records inside the supplied networks and
// returns the number removed. Event history is retained. Scanning once under
// the lock avoids a full database scan per address during startup cleanup.
func (db *DB) ForgetNetworks(nets []*net.IPNet) int {
	if len(nets) == 0 {
		return 0
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	dropped := 0
	for key := range db.records {
		if netutil.IPInAnyNet(net.ParseIP(key), nets) {
			delete(db.records, key)
			db.markDeletedLocked(key)
			dropped++
		}
	}
	return dropped
}
