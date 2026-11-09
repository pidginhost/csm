package checks

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A scan kills a process and then hands its findings to the alert dispatcher,
// which runs auto-kill over them again. The second pass must leave the
// finding alone, whether the first pass killed the process or refused it.
func TestAutoKillProcessesSkipsEvaluatedFindings(t *testing.T) {
	oldFS, oldKill := osFS, signalProcess
	osFS = &procMock{uid: "1001", exe: "/tmp/evil", uptime: 1_000, startTick: 1}
	signals := 0
	signalProcess = func(_ context.Context, _ int, _ syscall.Signal, verify func() error) error {
		signals++
		return verify()
	}
	t.Cleanup(func() { osFS, signalProcess = oldFS, oldKill })

	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.KillProcesses = true
	findings := []alert.Finding{{
		Severity:  alert.Critical,
		Check:     "suspicious_process",
		PID:       4242,
		Timestamp: time.Now(),
	}}

	if actions := AutoKillProcesses(context.Background(), cfg, findings); len(actions) != 1 {
		t.Fatalf("first pass actions = %+v, want one kill", actions)
	}
	if !findings[0].AutoProcessResponseEvaluated {
		t.Fatal("first pass did not mark the finding evaluated")
	}

	delivered := append([]alert.Finding(nil), findings...)
	if actions := AutoKillProcesses(context.Background(), cfg, delivered); len(actions) != 0 {
		t.Fatalf("second pass actions = %+v, want none", actions)
	}
	if signals != 1 {
		t.Fatalf("process signalled %d times, want 1", signals)
	}
}
