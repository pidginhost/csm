package daemon

import (
	"fmt"
	"os"

	"github.com/pidginhost/csm/internal/store"
)

// A pending manual apply must be settled before switching posture. Recovering
// it could restore an enforcing config or ruleset; ignoring it would abandon
// the operator's rollback deadline.
func (d *Daemon) checkObserveStartupRecovery() error {
	if !d.cfg.ObserveMode() {
		return nil
	}
	if db := store.Global(); db != nil {
		if _, pending := db.GetFirewallRollback(); pending {
			return fmt.Errorf("mode: observe cannot start with pending firewall settings recovery; resolve the pending apply in enforce mode before switching modes")
		}
	}
	marker, _, _ := firewallRollbackFiles(d.cfg.StatePath)
	if _, err := os.Stat(marker); err == nil {
		return fmt.Errorf("mode: observe cannot start with pending firewall rules recovery; resolve the pending apply in enforce mode before switching modes")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("mode: observe cannot check pending firewall recovery: %w", err)
	}
	return nil
}
