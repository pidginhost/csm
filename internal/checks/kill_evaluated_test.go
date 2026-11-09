package checks

import (
	"context"
	"encoding/json"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// A scan kills a process and then hands its findings to the alert dispatcher,
// which runs auto-kill over them again. The second pass must leave the
// finding alone, whether the first pass killed the process or refused it.
func TestAutoKillProcessesSkipsEvaluatedFindings(t *testing.T) {
	for _, check := range []string{"fake_kernel_thread", "suspicious_process", "php_suspicious_execution"} {
		for _, outcome := range []string{"killed", "refused", "exited", "failed", "canceled"} {
			t.Run(check+"/"+outcome, func(t *testing.T) {
				sink := withActionSink(t)
				calls := withSimulatedProcessSignal(t)
				proc := &procMock{uid: "1001", exe: "/tmp/evil", uptime: 1_000, startTick: 1}
				oldFS := osFS
				osFS = proc
				t.Cleanup(func() { osFS = oldFS })
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				wantResult, wantActions := actionlog.Applied, 1
				switch outcome {
				case "refused":
					proc.uid = "0"
					wantResult, wantActions = actionlog.Refused, 0
				case "exited", "failed":
					wantResult, wantActions = actionlog.Refused, 0
					signalErr := os.ErrProcessDone
					if outcome == "failed" {
						signalErr = syscall.EPERM
						wantResult = actionlog.Failed
					}
					signalProcess = func(_ context.Context, pid int, _ syscall.Signal, _ func() error) error {
						calls.requested = append(calls.requested, pid)
						return signalErr
					}
				case "canceled":
					cancel()
					wantResult, wantActions = actionlog.Failed, 0
				}
				cfg := &config.Config{}
				cfg.AutoResponse.Enabled, cfg.AutoResponse.KillProcesses = true, true
				findings := []alert.Finding{{Check: check, Severity: alert.Critical, PID: 4242, Timestamp: time.Now()}}

				if actions := AutoKillProcesses(ctx, cfg, findings); len(actions) != wantActions {
					t.Fatalf("first pass actions = %+v, want %d", actions, wantActions)
				}
				if len(calls.signaled) != wantActions {
					t.Fatalf("signals = %v, want %d", calls.signaled, wantActions)
				}
				attempts := len(calls.requested)
				if outcome == "canceled" && attempts != 0 {
					t.Fatalf("canceled evaluation requested handles: %v", calls.requested)
				}
				if outcome != "canceled" && (attempts != 1 || calls.requested[0] != 4242) {
					t.Fatalf("first pass requests = %v, want [4242]", calls.requested)
				}
				if len(sink.records) != 1 || sink.records[0].Result != wantResult || sink.records[0].Op != "respond.kill_process" || sink.records[0].FindingID != alert.FindingID(findings[0]) {
					t.Fatalf("first pass records = %+v, want one %s termination", sink.records, wantResult)
				}

				// Delivery uses a fresh context and copies the finding values.
				delivered := append([]alert.Finding(nil), findings...)
				if actions := AutoKillProcesses(context.Background(), cfg, delivered); len(actions) != 0 {
					t.Fatalf("second pass actions = %+v, want none", actions)
				}
				if len(calls.requested) != attempts || len(sink.records) != 1 {
					t.Fatalf("delivery retried termination: requests=%v records=%+v", calls.requested, sink.records)
				}
			})
		}
	}
}

func TestAutoKillProcessesReevaluatesStoredAndFreshFindings(t *testing.T) {
	sink := withActionSink(t)
	calls := withSimulatedProcessSignal(t)
	oldFS := osFS
	osFS = &procMock{uid: "1001", exe: "/tmp/evil", uptime: 1_000, startTick: 1}
	t.Cleanup(func() { osFS = oldFS })
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.KillProcesses = true, true
	original := alert.Finding{Check: "suspicious_process", Severity: alert.Critical, PID: 4242, Timestamp: time.Now()}
	findings := []alert.Finding{original}

	if actions := AutoKillProcesses(context.Background(), cfg, findings); len(actions) != 1 {
		t.Fatalf("first pass actions = %+v, want one kill", actions)
	}
	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	var restored []alert.Finding
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	for _, batch := range [][]alert.Finding{restored, {original}} {
		if actions := AutoKillProcesses(context.Background(), cfg, batch); len(actions) != 1 {
			t.Fatalf("fresh evaluation actions = %+v, want one kill", actions)
		}
		if actions := AutoKillProcesses(context.Background(), cfg, batch); len(actions) != 0 {
			t.Fatalf("fresh evaluation repeated a kill: %+v", actions)
		}
	}
	if len(calls.signaled) != 3 || len(calls.requested) != 3 || len(sink.records) != 3 {
		t.Fatalf("want three independent evaluations: requests=%v signals=%v records=%+v", calls.requested, calls.signaled, sink.records)
	}
}

func TestRunParallelProcessResponseSurvivesDelivery(t *testing.T) {
	for _, mode := range []string{"live", "dry run", "disabled", "kill disabled"} {
		t.Run(mode, func(t *testing.T) {
			sink := withActionSink(t)
			calls := withSimulatedProcessSignal(t)
			oldFS := osFS
			osFS = &procMock{uid: "1001", exe: "/tmp/evil", uptime: 1_000, startTick: 1}
			t.Cleanup(func() { osFS = oldFS })
			cfg := &config.Config{StatePath: t.TempDir()}
			cfg.AutoResponse.Enabled = mode != "disabled"
			cfg.AutoResponse.KillProcesses = mode != "kill disabled"
			checks := []namedCheck{{
				"synthetic_process",
				func(context.Context, *config.Config, *state.Store) []alert.Finding {
					return []alert.Finding{{Check: "suspicious_process", Severity: alert.Critical, PID: 4242}}
				},
			}}
			findings, _ := runParallel(cfg, nil, checks, "test", mode == "dry run")
			want := 0
			if mode == "live" {
				want = 1
			}
			if len(calls.signaled) != want || len(sink.records) != want || len(findings) != 1+want {
				t.Fatalf("runner signals=%v records=%+v findings=%+v, want %d kills", calls.signaled, sink.records, findings, want)
			}
			cfg.AutoResponse.Enabled, cfg.AutoResponse.KillProcesses = true, true
			delivered := append([]alert.Finding(nil), findings...)
			if actions := AutoKillProcesses(context.Background(), cfg, delivered); len(actions) != 1-want {
				t.Fatalf("delivery actions=%+v, want %d", actions, 1-want)
			}
			if len(calls.signaled) != 1 || len(calls.requested) != 1 || len(sink.records) != 1 {
				t.Fatalf("want one evaluation across runner and delivery: requests=%v signals=%v records=%+v", calls.requested, calls.signaled, sink.records)
			}
		})
	}
}
