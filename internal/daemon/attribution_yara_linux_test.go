//go:build linux && yara

package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// The realtime YARA match is emitted through sendAlertWithPath with the
// scanned file's path, so its owner resolves from the path.
func TestYARARealtimeFindingAttributesByPath(t *testing.T) {
	total, stamped := realtimeEmissionSites(t, []string{"yara_match_realtime"})
	if total["yara_match_realtime"] == 0 || total["yara_match_realtime"] != stamped["yara_match_realtime"] {
		t.Fatalf("yara_match_realtime: %d emission sites, %d carry a path", total["yara_match_realtime"], stamped["yara_match_realtime"])
	}
	alerts := make(chan alert.Finding, 1)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
	fm.sendAlertWithPath(alert.Critical, "yara_match_realtime", "YARA rule match [fixture]", "Matched 1 YARA rule(s)", "/home/alice/public_html/x.php", "")
	f := <-alerts
	requireOwner(t, []alert.Finding{f}, "yara_match_realtime", "")
	res := checks.CorrelateFindings([]alert.Finding{f,
		{Severity: alert.Critical, Check: "db_rogue_admin", TenantID: "carol"},
		{Severity: alert.Critical, Check: "db_rogue_admin", TenantID: "dave"}})
	if len(res.Derived) != 1 || len(res.Unattributed) != 0 {
		t.Fatalf("path-attributed YARA finding did not aggregate: %+v", res)
	}
}
