package daemon

import (
	"fmt"
	"net"
	"os"

	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/netutil"
)

func (d *Daemon) prepareAttackDatabase(adb *attackdb.DB) {
	d.registerQueueSource("attackdb", adb)
	// Seed from permanent blocklist on first run (when attack DB is empty)
	if adb.TotalIPs() == 0 {
		if n := adb.SeedFromPermanentBlocklist(d.cfg.StatePath); n > 0 {
			fmt.Fprintf(os.Stderr, "[%s] Attack DB seeded %d IPs from permanent blocklist\n", ts(), n)
		}
	}
	if n := forgetInfraAttackRecords(adb, d.cfg.InfraIPs); n > 0 {
		_ = adb.Flush()
		fmt.Fprintf(os.Stderr, "[%s] Attack DB dropped %d records inside infra_ips\n", ts(), n)
	}
	fmt.Fprintf(os.Stderr, "[%s] Attack DB initialized (%s)\n", ts(), adb.FormatTopLine())
}

// forgetInfraAttackRecords drops the records of addresses inside infra_ips.
// An address listed after it was recorded would otherwise stay ranked as an
// attacker until its record expires. Hostname entries are skipped: the checks
// match only literal addresses and CIDRs, so a resolved address is still
// recorded and dropping it here would only hide it until the next finding.
func forgetInfraAttackRecords(adb *attackdb.DB, infraIPs []string) int {
	var nets []*net.IPNet
	for _, entry := range infraIPs {
		if n := netutil.ParseCIDROrIP(entry); n != nil {
			nets = append(nets, n)
		}
	}
	if len(nets) == 0 {
		return 0
	}
	dropped := 0
	for _, rec := range adb.AllRecords() {
		if ip := net.ParseIP(rec.IP); ip != nil && netutil.IPInAnyNet(ip, nets) {
			dropped += len(adb.ForgetIP(ip))
		}
	}
	return dropped
}
