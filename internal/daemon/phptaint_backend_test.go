package daemon

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/workerproc"
)

// stubPHPTaintUnits replaces the unit seams and records what init asked for.
func stubPHPTaintUnits(t *testing.T) (stopped *[]string, units *[]workerproc.UnitConfig) {
	t.Helper()
	stopped, units = new([]string), new([]workerproc.UnitConfig)
	realStop, realLauncher, realHidden := stopParseWorkerUnits, phpTaintWorkerLauncher, parseWorkerHiddenPaths
	stopParseWorkerUnits = func(_ context.Context, prefix string) error {
		*stopped = append(*stopped, prefix)
		return nil
	}
	phpTaintWorkerLauncher = func(cfg workerproc.UnitConfig) workerproc.Launcher {
		*units = append(*units, cfg)
		return func(context.Context) (workerproc.Process, error) { return nil, errors.New("no units in tests") }
	}
	parseWorkerHiddenPaths = func() []string { return []string{"/home2"} }
	t.Cleanup(func() {
		stopParseWorkerUnits, phpTaintWorkerLauncher, parseWorkerHiddenPaths = realStop, realLauncher, realHidden
	})
	return stopped, units
}

func TestPHPTaintAnalyzerLifecycleInstallsLazySupervisor(t *testing.T) {
	stubPHPTaintUnits(t)
	allowParseWorkerCommand(t)
	d := &Daemon{binaryPath: "/opt/csm/csm"}
	if err := d.initPHPTaintAnalyzer(); err != nil {
		t.Fatal(err)
	}
	if d.phpTaintSup == nil {
		t.Fatal("PHP taint supervisor was not installed")
	}
	if got := d.phpTaintSup.SpawnCount(); got != 0 {
		t.Fatalf("worker spawned during initialization: %d", got)
	}
	q, ok := d.QueueStatuses()["php_taint.requests"]
	if !ok || q.Status != "ok" || !q.CapacityUnavailable || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("PHP worker queue was not published: found=%v status=%+v", ok, q)
	}

	d.stopPHPTaintAnalyzer()
	if d.phpTaintSup != nil {
		t.Fatal("PHP taint supervisor survived shutdown")
	}
	if q, ok := d.QueueStatuses()["php_taint.requests"]; !ok || q.Status != "ok" || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("stopped worker health was discarded: found=%v status=%+v", ok, q)
	}
}

func TestPHPTaintAnalyzerRejectsMissingBinary(t *testing.T) {
	d := &Daemon{}
	if err := d.initPHPTaintAnalyzer(); err == nil {
		t.Fatal("empty worker command was accepted")
	}
	if d.phpTaintSup != nil {
		t.Fatal("failed initialization retained a supervisor")
	}
}

func TestPHPTaintAnalyzerUsesLockedDownUnits(t *testing.T) {
	stopped, units := stubPHPTaintUnits(t)
	allowParseWorkerCommand(t)
	d := &Daemon{binaryPath: "/opt/csm/csm"}
	if err := d.initPHPTaintAnalyzer(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.stopPHPTaintAnalyzer)
	if !slices.Equal(*stopped, []string{"csm-phptaint-worker-"}) {
		t.Fatalf("leftover units stopped with %q", *stopped)
	}
	if len(*units) != 1 {
		t.Fatalf("unit configs = %d, want 1", len(*units))
	}
	cfg := (*units)[0]
	if cfg.Prefix != "csm-phptaint-worker" || !slices.Equal(cfg.InaccessiblePaths, []string{"/home2"}) {
		t.Fatalf("unit prefix %q, hidden %q", cfg.Prefix, cfg.InaccessiblePaths)
	}
	if cfg.Command != d.binaryPath || len(cfg.Args) == 0 || cfg.Args[0] != "phptaint-worker" {
		t.Fatalf("unit runs %q %q", cfg.Command, cfg.Args)
	}
}

// A unit's dynamic user cannot run an owner-only binary: refuse once at init
// instead of failing every analysis at exec.
func TestPHPTaintAnalyzerRejectsUnexecutableBinary(t *testing.T) {
	stubPHPTaintUnits(t)
	real := checkParseWorkerCommand
	checkParseWorkerCommand = func(string) error { return errors.New("binary is owner-only") }
	t.Cleanup(func() { checkParseWorkerCommand = real })
	d := &Daemon{binaryPath: "/opt/csm/csm"}
	if err := d.initPHPTaintAnalyzer(); err == nil {
		t.Fatal("owner-only binary was accepted")
	}
	if d.phpTaintSup != nil {
		t.Fatal("failed initialization retained a supervisor")
	}
}
