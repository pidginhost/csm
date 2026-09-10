package daemon

import (
	"fmt"
	"os"

	"github.com/pidginhost/csm/internal/attackdb"
)

func (d *Daemon) prepareAttackDatabase(adb *attackdb.DB) {
	d.registerQueueSource("attackdb", adb)
	// Seed from permanent blocklist on first run (when attack DB is empty)
	if adb.TotalIPs() == 0 {
		if n := adb.SeedFromPermanentBlocklist(d.cfg.StatePath); n > 0 {
			fmt.Fprintf(os.Stderr, "[%s] Attack DB seeded %d IPs from permanent blocklist\n", ts(), n)
		}
	}
	fmt.Fprintf(os.Stderr, "[%s] Attack DB initialized (%s)\n", ts(), adb.FormatTopLine())
}
