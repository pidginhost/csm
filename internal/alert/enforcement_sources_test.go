package alert

import (
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestEnforcementSourcesStayOffNotificationChannels(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		for _, notify := range []bool{false, true} {
			t.Run(fmt.Sprintf("enforce=%t/notify=%t", enforce, notify), func(t *testing.T) {
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
						t.Errorf("central received invalid source: %+v", f)
					}
				})
				SetReportHook(func(Finding) { report++ })
				bus := &stubBus{}
				FindingBus = bus
				f := Finding{Check: "smtp_bruteforce", SourceIP: "192.0.2.50", Severity: Critical}
				sources := []Finding{f, f}
				var notifications []Finding
				if notify {
					notifications = []Finding{f}
				}
				dispatch := DispatchWithSources
				if enforce {
					dispatch = DispatchWithEnforcement
				}
				if err := dispatch(&config.Config{}, notifications, sources); err != nil {
					t.Fatal(err)
				}
				wantCentral := 0
				if enforce || notify {
					wantCentral = 1
				}
				if central != wantCentral || report != len(notifications) || int(bus.publishCount.Load()) != len(notifications) {
					t.Fatalf("central=%d report=%d bus=%d; want %d/%d/%d", central, report, bus.publishCount.Load(), wantCentral, len(notifications), len(notifications))
				}
				if !sources[0].Timestamp.IsZero() || !sources[1].Timestamp.IsZero() || (notify && !notifications[0].Timestamp.IsZero()) {
					t.Fatal("dispatch changed caller-owned observations")
				}
			})
		}
	}
}
