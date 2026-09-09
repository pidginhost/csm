//go:build linux

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/processhandle"
)

func TestAFAlgReactionVerifiesAfterAcquiringHandle(t *testing.T) {
	for _, reason := range []string{"eligible", "root transition", "stale", "unsupported"} {
		t.Run(reason, func(t *testing.T) {
			sink := captureActionRecords(t)
			fakeAFAlgProc(t, 4242, "/tmp/offender", 1000, 100)
			status := filepath.Join(procRootDir, "4242", "status")
			if err := os.WriteFile(status, []byte("Uid:\t1001\t1001\t1001\t1001\n"), 0600); err != nil {
				t.Fatal(err)
			}
			ev := checks.AFAlgEvent{PID: "4242", Exe: "/tmp/offender", UID: "1001", Timestamp: eventTimestamp(time.Second)}
			if reason == "stale" {
				ev.Timestamp = eventTimestamp(950 * time.Second)
			}
			old := signalAFAlgProcess
			t.Cleanup(func() { signalAFAlgProcess = old })
			opened, verified, signaled := 0, 0, 0
			signalAFAlgProcess = func(ctx context.Context, pid int, sig syscall.Signal, verify func() error) error {
				if ctx == nil || pid != 4242 || sig != syscall.SIGKILL {
					t.Fatalf("signal target=%d signal=%d", pid, sig)
				}
				opened++
				if reason == "unsupported" {
					return processhandle.ErrUnsupported
				}
				if reason == "root transition" {
					if err := os.WriteFile(status, []byte("Uid:\t1001\t0\t1001\t1001\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				verified++
				if err := verify(); err != nil {
					return err
				}
				signaled++
				return nil
			}
			cfg := &config.Config{}
			cfg.AutoResponse.CopyFailKillProcess = true
			reactToAFAlgEvent(cfg, ev)
			wantResult := actionlog.Refused
			if reason == "eligible" {
				wantResult = actionlog.Applied
			}
			if reason == "unsupported" {
				wantResult = actionlog.Failed
			}
			if len(sink.records) != 1 || sink.records[0].Op != "respond.kill_process" || sink.records[0].Result != wantResult {
				t.Fatalf("records=%+v", sink.records)
			}
			wantSignals, wantVerify := 0, 1
			if reason == "eligible" {
				wantSignals = 1
			}
			if reason == "unsupported" {
				wantVerify = 0
			}
			if opened != 1 || verified != wantVerify || signaled != wantSignals {
				t.Fatalf("open/verify/signal=%d/%d/%d want=1/%d/%d", opened, verified, signaled, wantVerify, wantSignals)
			}
		})
	}
}
