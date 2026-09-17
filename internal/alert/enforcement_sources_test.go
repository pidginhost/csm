package alert

import (
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// Central enforcement is offered exactly the enforcement set, deduplicated,
// whatever reaches the notification channels. Report hooks and passive
// observers stay tied to notifications.
func TestEnforcementFindingsStayOffNotificationChannels(t *testing.T) {
	for _, notify := range []bool{false, true} {
		t.Run(fmt.Sprintf("notify=%t", notify), func(t *testing.T) {
			previousCentral, previousReport, previousBus := currentCentralHook(), currentReportHook(), FindingBus
			t.Cleanup(func() {
				SetCentralHook(previousCentral)
				SetReportHook(previousReport)
				FindingBus = previousBus
			})
			var central, report int
			SetCentralHook(func(f Finding) {
				central++
				if f.SourceIP != "192.0.2.50" || f.Timestamp.IsZero() {
					t.Errorf("central received invalid finding: %+v", f)
				}
			})
			SetReportHook(func(Finding) { report++ })
			bus := &stubBus{}
			FindingBus = bus
			f := Finding{Check: "smtp_bruteforce", SourceIP: "192.0.2.50", Severity: Critical}
			raw := Finding{Check: "email_auth_failure_realtime", SourceIP: "192.0.2.51", Severity: High}
			sources := []Finding{f, raw}
			enforcement := []Finding{f, f}
			var notifications []Finding
			if notify {
				notifications = []Finding{f}
			}
			if err := DispatchWithEnforcement(&config.Config{}, notifications, sources, enforcement); err != nil {
				t.Fatal(err)
			}
			if central != 1 || report != len(notifications) || int(bus.publishCount.Load()) != len(notifications) {
				t.Fatalf("central=%d report=%d bus=%d; want 1/%d/%d", central, report, bus.publishCount.Load(), len(notifications), len(notifications))
			}
			if !enforcement[0].Timestamp.IsZero() || !sources[0].Timestamp.IsZero() || (notify && !notifications[0].Timestamp.IsZero()) {
				t.Fatal("dispatch changed caller-owned findings")
			}
		})
	}
}
