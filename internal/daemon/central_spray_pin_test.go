package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/reporting"
)

// Central intelligence never acts on a password spray: its subnet is not a
// listed address, even when the network address itself is listed.
func TestSprayPinCentralIgnoresTheSubnet(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	store := centralStoreWith(t, []reporting.ScoredEntry{
		{IP: "198.51.100.0", Score: 95, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Unix(1_700_000_000, 0).UTC()},
	})
	notProtected := func(string) bool { return false }
	for _, check := range []string{"mail_subnet_spray", "smtp_subnet_spray"} {
		f := alert.Finding{Check: check, Severity: alert.Critical, SourceIP: "198.51.100.0/24"}
		if action, ok := d.planCentralAction(store, reporting.ActionBlockIfLocalCorroborated, 80, notProtected, f); ok {
			t.Errorf("%s: planned %+v, want no central action", check, action)
		}
	}
}
