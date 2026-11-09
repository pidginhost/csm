package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

func TestProcessResponseDelivery(t *testing.T) {
	for _, path := range []string{"startup", "dispatch", "realtime", "replay"} {
		t.Run(path, func(t *testing.T) {
			resetIncidentForTest()
			t.Cleanup(resetIncidentForTest)
			sink := captureActionRecords(t)
			cfg := &config.Config{StatePath: t.TempDir()}
			cfg.AutoResponse.Enabled, cfg.AutoResponse.KillProcesses = true, true
			d := suppressionTestDaemon(t, cfg, nil)
			// A canceled context prevents any kernel signal. Each attempted
			// response still records its outcome, exposing duplicate evaluation.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			d.scanCtx = ctx
			findings := []alert.Finding{{Check: "suspicious_process", Severity: alert.Critical, PID: 4242, Timestamp: time.Now()}}
			if path != "realtime" {
				checks.AutoKillProcesses(ctx, cfg, findings)
				if len(sink.records) != 1 {
					t.Fatalf("scan records=%+v, want one termination attempt", sink.records)
				}
			}
			switch path {
			case "startup":
				d.respondToInitialScan(cfg, findings)
			case "dispatch":
				d.enqueueScanAlerts(findings, "test")
				delivered := drainAlertCh(d)
				if len(delivered) != 1 {
					t.Fatalf("delivered=%+v, want one scan finding", delivered)
				}
				d.dispatchBatch(delivered)
			case "realtime":
				d.dispatchBatch(findings)
			case "replay":
				if err := d.store.AppendPendingFindings(findings); err != nil {
					t.Fatal(err)
				}
				d.replayPendingFindings()
			}
			want := 1
			if path == "replay" {
				want = 2
			}
			if len(sink.records) != want {
				t.Fatalf("records=%+v, want %d termination attempts", sink.records, want)
			}
			for _, rec := range sink.records {
				if rec.Op != "respond.kill_process" || rec.Result != actionlog.Failed || rec.FindingID != alert.FindingID(findings[0]) || rec.Error != context.Canceled.Error() {
					t.Fatalf("unexpected termination record: %+v", rec)
				}
			}
		})
	}
}
