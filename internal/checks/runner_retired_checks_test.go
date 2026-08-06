package checks

import "testing"

// retiredCheckNames are check names no longer emitted by any production
// code path but still present in the findings store of hosts upgrading
// from an older CSM.
//
// A finding is only ever cleared when its check name appears in the
// owning runner's purge list. Dropping a retired name from that list
// leaves every stored finding of that kind stuck in the active view
// forever, because nothing re-emits it and nothing purges it.
var retiredCheckNames = map[string]string{
	// Removed once modsec_disabled_vhost replaced it; the old
	// implementation misparsed disabled rules as disabled domains.
	"waf_bypass": "waf_status",
}

func TestRetiredCheckNamesStayPurgeable(t *testing.T) {
	for name, runner := range retiredCheckNames {
		purged := false
		for _, candidate := range runnerFindingNames[runner] {
			if candidate == name {
				purged = true
				break
			}
		}
		if !purged {
			t.Errorf("retired check %q is not in runnerFindingNames[%q], so findings written by older versions can never be cleared", name, runner)
		}
	}
}
